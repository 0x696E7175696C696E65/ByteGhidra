#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <winioctl.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {

constexpr DWORD CodeSecurity = 0x085b3b69;
constexpr DWORD IoctlReadWrite = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1645, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD IoctlBaseAddress = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1646, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD IoctlHandshake = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1648, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD IoctlAllocVm = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1649, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

constexpr uint64_t RvaUserSession = 0x1d72f90;
constexpr uint64_t RvaKillSwitchRegistry = 0x1fa33c0;
constexpr uint64_t RvaLicenseSuppression = 0x1fcf410;
constexpr uint64_t RvaXGameRuntimeReady = 0x2f235a8;
constexpr uint64_t RvaBapOutstandingReq = 0x1f5bb8c;

constexpr uint64_t KillSwitchTableOffset = 0x19808;
constexpr size_t KillSwitchCount = 512;

constexpr uint64_t SessionTokenOffset = 0x108;
constexpr uint64_t SessionSessionIdOffset = 0x138;
constexpr uint64_t SessionUserIdOffset = 0x5c0;
constexpr int32_t FakeUserId = 1;
constexpr int32_t FakeSessionId = 1;
constexpr char FakeToken[] = "D2PrivateServerToken_v1";

std::ofstream gLog;

std::string exe_directory() {
    char path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (length == 0 || length == MAX_PATH) {
        return ".";
    }

    std::string result(path, length);
    const size_t slash = result.find_last_of("\\/");
    return slash == std::string::npos ? "." : result.substr(0, slash);
}

void checkpoint(const std::string& message) {
    std::cout << message << "\n";
    if (gLog.is_open()) {
        SYSTEMTIME now{};
        GetLocalTime(&now);
        gLog << std::setfill('0')
             << "[" << std::setw(2) << now.wHour
             << ":" << std::setw(2) << now.wMinute
             << ":" << std::setw(2) << now.wSecond
             << "." << std::setw(3) << now.wMilliseconds
             << "] " << message << std::setfill(' ') << "\n";
        gLog.flush();
    }
}

LONG WINAPI unhandled_exception_filter(EXCEPTION_POINTERS* exceptionInfo) {
    if (gLog.is_open() && exceptionInfo && exceptionInfo->ExceptionRecord) {
        gLog << "[CRASH] code=0x" << std::hex << exceptionInfo->ExceptionRecord->ExceptionCode
             << " address=0x" << reinterpret_cast<uintptr_t>(exceptionInfo->ExceptionRecord->ExceptionAddress)
             << std::dec << "\n";
        gLog.flush();
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

struct HandshakeIo {
    int32_t magic;
    int32_t clientPid;
    uint64_t sessionToken;
};

struct RwIo {
    int32_t security;
    int32_t processId;
    uint64_t address;
    uint64_t buffer;
    uint64_t size;
    BOOLEAN write;
    uint64_t sessionToken;
};

struct BaseAddressIo {
    int32_t security;
    int32_t processId;
    uint64_t addressPointer;
    uint64_t sessionToken;
};

struct AllocVmIo {
    int32_t security;
    int32_t processId;
    uint64_t size;
    uint64_t address;
    uint64_t sessionToken;
};

static_assert(sizeof(HandshakeIo) == 16);
static_assert(sizeof(RwIo) == 48);
static_assert(sizeof(BaseAddressIo) == 24);
static_assert(sizeof(AllocVmIo) == 32);

std::wstring widen(const std::string& value) {
    if (value.empty()) {
        return {};
    }

    const int needed = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (needed <= 0) {
        return {};
    }

    std::wstring result(static_cast<size_t>(needed - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), needed);
    return result;
}

std::string narrow(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }

    std::string result(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), needed, nullptr, nullptr);
    return result;
}

std::string last_error_message(DWORD error = GetLastError()) {
    LPSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = FormatMessageA(flags, nullptr, error, 0, reinterpret_cast<LPSTR>(&buffer), 0, nullptr);
    std::string message = length ? std::string(buffer, length) : "unknown error";
    if (buffer) {
        LocalFree(buffer);
    }

    while (!message.empty() && (message.back() == '\r' || message.back() == '\n' || message.back() == ' ')) {
        message.pop_back();
    }

    return message + " (" + std::to_string(error) + ")";
}

uint32_t find_process_id(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] CreateToolhelp32Snapshot failed: " << last_error_message() << "\n";
        return 0;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    uint32_t pid = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::wstring exe = entry.szExeFile;
            std::transform(exe.begin(), exe.end(), exe.begin(), ::towlower);
            if (exe == processName) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

std::vector<std::wstring> enumerate_dos_device_paths() {
    DWORD chars = 32768;
    std::vector<wchar_t> buffer(chars);

    while (!QueryDosDeviceW(nullptr, buffer.data(), chars)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return {};
        }
        chars *= 2;
        buffer.assign(chars, L'\0');
    }

    std::vector<std::wstring> paths;
    for (const wchar_t* cursor = buffer.data(); *cursor; cursor += wcslen(cursor) + 1) {
        std::wstring name(cursor);
        if (name.size() == 2 && name[1] == L':') {
            continue;
        }
        if (name.rfind(L"GLOBALROOT", 0) == 0) {
            continue;
        }
        paths.push_back(LR"(\\.\)" + name);
    }

    return paths;
}

class DriverClient {
public:
    ~DriverClient() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    DriverClient(const DriverClient&) = delete;
    DriverClient& operator=(const DriverClient&) = delete;

    DriverClient(DriverClient&& other) noexcept {
        handle_ = other.handle_;
        devicePath_ = std::move(other.devicePath_);
        sessionToken_ = other.sessionToken_;
        other.handle_ = INVALID_HANDLE_VALUE;
        other.sessionToken_ = 0;
    }

    DriverClient& operator=(DriverClient&& other) noexcept {
        if (this != &other) {
            if (handle_ != INVALID_HANDLE_VALUE) {
                CloseHandle(handle_);
            }
            handle_ = other.handle_;
            devicePath_ = std::move(other.devicePath_);
            sessionToken_ = other.sessionToken_;
            other.handle_ = INVALID_HANDLE_VALUE;
            other.sessionToken_ = 0;
        }
        return *this;
    }

    static DriverClient connect(const std::wstring& explicitDevice) {
        std::vector<std::wstring> candidates;
        if (!explicitDevice.empty()) {
            candidates.push_back(explicitDevice);
        }

        candidates.push_back(LR"(\\.\D2PatchDriver)");
        candidates.push_back(LR"(\\.\JbKpiuhC4Ga4DqWsL9X2pE)");
        candidates.push_back(LR"(\\.\f5e19fba-b202-41a2-8826-26cbe6891bc7)");

        const auto enumerated = enumerate_dos_device_paths();
        candidates.insert(candidates.end(), enumerated.begin(), enumerated.end());

        std::vector<std::wstring> seen;
        for (const auto& path : candidates) {
            if (std::find(seen.begin(), seen.end(), path) != seen.end()) {
                continue;
            }
            seen.push_back(path);

            HANDLE handle = CreateFileW(
                path.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (handle == INVALID_HANDLE_VALUE) {
                if (!explicitDevice.empty() && path == explicitDevice) {
                    std::cerr << "[!] CreateFile failed for " << narrow(path) << ": " << last_error_message() << "\n";
                }
                continue;
            }

            HandshakeIo handshake{};
            handshake.magic = static_cast<int32_t>(CodeSecurity);
            handshake.clientPid = static_cast<int32_t>(GetCurrentProcessId());

            DWORD bytes = 0;
            const BOOL ok = DeviceIoControl(
                handle,
                IoctlHandshake,
                &handshake,
                sizeof(handshake),
                &handshake,
                sizeof(handshake),
                &bytes,
                nullptr);

            if (ok && bytes == sizeof(handshake) && handshake.sessionToken != 0) {
                std::cout << "[+] Connected to driver at " << narrow(path) << "\n";
                DriverClient client;
                client.handle_ = handle;
                client.devicePath_ = path;
                client.sessionToken_ = handshake.sessionToken;
                return client;
            }

            const DWORD err = GetLastError();
            CloseHandle(handle);

            if (!explicitDevice.empty() && path == explicitDevice) {
                std::cerr << "[!] Handshake failed for " << narrow(path) << ": " << last_error_message(err) << "\n";
            }
        }

        throw std::runtime_error(
            "Could not find a loaded driver that accepts the D2 patcher handshake. "
            "Rebuild/reload the updated driver or pass --device \\\\.\\YourDeviceName.");
    }

    uint64_t base_address(uint32_t pid) {
        uint64_t base = 0;
        BaseAddressIo req{};
        req.security = static_cast<int32_t>(CodeSecurity);
        req.processId = static_cast<int32_t>(pid);
        req.addressPointer = reinterpret_cast<uint64_t>(&base);
        req.sessionToken = sessionToken_;

        DWORD bytes = 0;
        if (!DeviceIoControl(handle_, IoctlBaseAddress, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr) || !base) {
            throw std::runtime_error("base-address IOCTL failed: " + last_error_message());
        }

        return base;
    }

    uint64_t allocate(uint32_t pid, uint64_t size) {
        AllocVmIo req{};
        req.security = static_cast<int32_t>(CodeSecurity);
        req.processId = static_cast<int32_t>(pid);
        req.size = size;
        req.sessionToken = sessionToken_;

        DWORD bytes = 0;
        if (DeviceIoControl(handle_, IoctlAllocVm, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr) && req.address) {
            return req.address;
        }

        const DWORD ioctlError = GetLastError();
        std::cerr << "[!] Driver allocation IOCTL failed: " << last_error_message(ioctlError) << "\n";
        checkpoint("[!] Driver allocation IOCTL failed: driver allocation IOCTL is unavailable or denied.");
        checkpoint("[!] Rebuild/reload the updated driver source that supports IOCTL 0x1649 before patching user session.");
        std::cerr << "[!] Falling back to VirtualAllocEx for token storage.\n";

        HANDLE process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) {
            throw std::runtime_error(
                "OpenProcess fallback failed: " + last_error_message() +
                ". The protected target blocks user-mode allocation; rebuild/reload the updated driver.");
        }

        void* remote = VirtualAllocEx(process, nullptr, static_cast<SIZE_T>(size), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        const DWORD allocError = GetLastError();
        CloseHandle(process);

        if (!remote) {
            throw std::runtime_error(
                "VirtualAllocEx fallback failed: " + last_error_message(allocError) +
                ". The protected target blocks user-mode allocation; rebuild/reload the updated driver.");
        }

        return reinterpret_cast<uint64_t>(remote);
    }

    bool read(uint32_t pid, uint64_t address, void* buffer, size_t size) {
        return transfer(pid, address, buffer, size, false);
    }

    bool write(uint32_t pid, uint64_t address, const void* buffer, size_t size) {
        return transfer(pid, address, const_cast<void*>(buffer), size, true);
    }

private:
    DriverClient() = default;

    bool transfer(uint32_t pid, uint64_t address, void* buffer, size_t size, bool isWrite) {
        size_t offset = 0;
        while (offset < size) {
            const uint64_t currentAddress = address + offset;
            const size_t pageRemaining = 0x1000 - static_cast<size_t>(currentAddress & 0xfff);
            const size_t chunk = std::min(size - offset, pageRemaining);

            RwIo req{};
            req.security = static_cast<int32_t>(CodeSecurity);
            req.processId = static_cast<int32_t>(pid);
            req.address = currentAddress;
            req.buffer = reinterpret_cast<uint64_t>(static_cast<uint8_t*>(buffer) + offset);
            req.size = chunk;
            req.write = isWrite ? TRUE : FALSE;
            req.sessionToken = sessionToken_;

            DWORD bytes = 0;
            if (!DeviceIoControl(handle_, IoctlReadWrite, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr)) {
                std::cerr << "[!] " << (isWrite ? "Write" : "Read") << " IOCTL failed at 0x"
                          << std::hex << currentAddress << std::dec << ": " << last_error_message() << "\n";
                return false;
            }

            offset += chunk;
        }

        return true;
    }

    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::wstring devicePath_;
    uint64_t sessionToken_ = 0;
};

template <typename T>
bool write_value(DriverClient& driver, uint32_t pid, uint64_t address, const T& value) {
    return driver.write(pid, address, &value, sizeof(T));
}

bool patch_xgameruntime(DriverClient& driver, uint32_t pid, uint64_t base) {
    const uint8_t one = 1;
    if (!write_value(driver, pid, base + RvaXGameRuntimeReady, one)) {
        return false;
    }
    std::cout << "[+] XGameRuntime ready flag set\n";

    if (!write_value(driver, pid, base + RvaLicenseSuppression, one)) {
        return false;
    }
    std::cout << "[+] License check disabled\n";
    return true;
}

bool is_canonical_user_pointer(uint64_t value) {
    return value >= 0x10000 && value < 0x0000800000000000ULL;
}

bool patch_kill_switches(DriverClient& driver, uint32_t pid, uint64_t base) {
    uint64_t registry = 0;
    const uint64_t registryGlobal = base + RvaKillSwitchRegistry;
    std::cout << "[*] Reading kill-switch registry pointer at 0x"
              << std::hex << registryGlobal << std::dec << "\n";

    for (int attempt = 1; attempt <= 6; ++attempt) {
        registry = 0;
        if (!driver.read(pid, registryGlobal, &registry, sizeof(registry))) {
            std::cerr << "[!] Could not read kill-switch registry pointer\n";
            return false;
        }

        if (is_canonical_user_pointer(registry)) {
            break;
        }

        std::cerr << "[!] Kill-switch registry pointer attempt " << attempt
                  << " returned non-canonical value 0x" << std::hex << registry
                  << std::dec << "\n";

        if (registry == 0) {
            std::cerr << "[!] Registry may not be initialized yet; retrying...\n";
        }
        else {
            std::cerr << "[!] The g_killswitch_registry RVA may be stale for this game build.\n";
            break;
        }

        Sleep(2000);
    }

    if (!is_canonical_user_pointer(registry)) {
        std::cerr << "[!] Skipping kill-switch table patch to avoid writing to an invalid address.\n";
        std::cerr << "[!] Other auth/session patches will continue.\n";
        return true;
    }

    std::cout << "[*] Kill-switch registry pointer: 0x" << std::hex << registry << std::dec << "\n";
    std::vector<uint32_t> table(KillSwitchCount, 5);
    if (!driver.write(pid, registry + KillSwitchTableOffset, table.data(), table.size() * sizeof(uint32_t))) {
        std::cerr << "[!] Kill-switch table write failed; continuing with remaining patches.\n";
        std::cerr << "[!] This usually means the kill-switch RVA/table layout changed for this build.\n";
        return true;
    }

    std::cout << "[+] Kill switches patched (" << KillSwitchCount << " gates disabled)\n";
    return true;
}

bool patch_user_session(DriverClient& driver, uint32_t pid, uint64_t base) {
    const uint64_t session = base + RvaUserSession;
    const uint64_t tokenAddress = driver.allocate(pid, 64);

    if (!driver.write(pid, tokenAddress, FakeToken, sizeof(FakeToken))) {
        return false;
    }

    if (!write_value(driver, pid, session + SessionUserIdOffset, FakeUserId)) {
        return false;
    }

    if (!write_value(driver, pid, session + SessionSessionIdOffset, FakeSessionId)) {
        return false;
    }

    if (!write_value(driver, pid, session + SessionTokenOffset, tokenAddress)) {
        return false;
    }

    std::cout << "[+] User session patched (token @ 0x" << std::hex << tokenAddress << std::dec << ")\n";
    return true;
}

bool patch_outstanding_requests(DriverClient& driver, uint32_t pid, uint64_t base) {
    const uint32_t zero = 0;
    if (!write_value(driver, pid, base + RvaBapOutstandingReq, zero)) {
        return false;
    }

    std::cout << "[+] BAP outstanding request counter zeroed\n";
    return true;
}

void print_usage() {
    std::cout << "Usage: d2_driver_patcher.exe [--device \\\\.\\D2PatchDriver] [--wait seconds] [--scan-only] [--pause]\n"
              << "                             [--with-kill-switches] [--only xg|kill|session|bap]\n";
}

void pause_if_requested(bool pause) {
    if (!pause) {
        return;
    }

    std::cout << "\nPress Enter to exit...";
    std::cin.get();
}

} // namespace

int main(int argc, char** argv) {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    gLog.open(exe_directory() + "\\d2_driver_patcher_last.log", std::ios::out | std::ios::trunc);
    SetUnhandledExceptionFilter(unhandled_exception_filter);
    checkpoint("[*] Patcher process started");

    std::wstring explicitDevice;
    int waitSeconds = 10;
    bool scanOnly = false;
    bool pauseOnExit = false;
    bool patchXg = true;
    bool patchKill = false;
    bool patchSession = true;
    bool patchBap = true;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        }
        if (arg == "--device" && i + 1 < argc) {
            explicitDevice = widen(argv[++i]);
            continue;
        }
        if (arg == "--wait" && i + 1 < argc) {
            waitSeconds = std::max(0, std::atoi(argv[++i]));
            continue;
        }
        if (arg == "--scan-only") {
            scanOnly = true;
            continue;
        }
        if (arg == "--pause") {
            pauseOnExit = true;
            continue;
        }
        if (arg == "--with-kill-switches") {
            patchKill = true;
            continue;
        }
        if (arg == "--only" && i + 1 < argc) {
            const std::string only = argv[++i];
            patchXg = false;
            patchKill = false;
            patchSession = false;
            patchBap = false;

            if (only == "xg") {
                patchXg = true;
            }
            else if (only == "kill") {
                patchKill = true;
            }
            else if (only == "session") {
                patchSession = true;
            }
            else if (only == "bap") {
                patchBap = true;
            }
            else {
                std::cerr << "[!] Unknown --only value: " << only << "\n";
                print_usage();
                return 2;
            }
            continue;
        }

        std::cerr << "[!] Unknown argument: " << arg << "\n";
        print_usage();
        return 2;
    }

    try {
        checkpoint("=======================================================");
        checkpoint("  DESTINY 2 DRIVER-BACKED MEMORY PATCHER");
        checkpoint("=======================================================");

        checkpoint("[*] Connecting to driver...");
        auto driver = DriverClient::connect(explicitDevice);
        if (scanOnly) {
            checkpoint("[+] Driver handshake succeeded.");
            pause_if_requested(pauseOnExit);
            return 0;
        }

        checkpoint("[*] Searching for destiny2.exe...");
        const uint32_t pid = find_process_id(L"destiny2.exe");
        if (!pid) {
            std::cerr << "[!] destiny2.exe not found. Launch the game first.\n";
            checkpoint("[!] destiny2.exe not found");
            return 1;
        }
        std::cout << "[+] Found destiny2.exe PID: " << pid << "\n";

        checkpoint("[*] Requesting module base...");
        const uint64_t base = driver.base_address(pid);
        std::cout << "[+] Module base: 0x" << std::hex << base << std::dec << "\n";

        if (waitSeconds > 0) {
            std::cout << "[*] Waiting " << waitSeconds << "s for login-screen initialization...\n";
            checkpoint("[*] Entering wait");
            Sleep(static_cast<DWORD>(waitSeconds) * 1000);
            checkpoint("[*] Wait complete");
        }

        checkpoint("[*] Applying patches");
        if (patchXg) {
            checkpoint("[*] Patch begin: XGameRuntime/license flags");
            if (!patch_xgameruntime(driver, pid, base)) {
                checkpoint("[!] Patch failed: XGameRuntime/license flags");
                pause_if_requested(pauseOnExit);
                return 1;
            }
            checkpoint("[+] Patch done: XGameRuntime/license flags");
        }
        else {
            checkpoint("[*] Skipping XGameRuntime/license flags");
        }

        if (patchKill) {
            checkpoint("[*] Patch begin: kill switches");
            if (!patch_kill_switches(driver, pid, base)) {
                checkpoint("[!] Patch failed: kill switches");
                pause_if_requested(pauseOnExit);
                return 1;
            }
            checkpoint("[+] Patch done: kill switches");
        }
        else {
            checkpoint("[*] Skipping kill switches. Use --with-kill-switches after updating the RVA.");
        }

        if (patchSession) {
            checkpoint("[*] Patch begin: user session");
            if (!patch_user_session(driver, pid, base)) {
                checkpoint("[!] Patch failed: user session");
                pause_if_requested(pauseOnExit);
                return 1;
            }
            checkpoint("[+] Patch done: user session");
        }
        else {
            checkpoint("[*] Skipping user session");
        }

        if (patchBap) {
            checkpoint("[*] Patch begin: BAP outstanding requests");
            if (!patch_outstanding_requests(driver, pid, base)) {
                checkpoint("[!] Patch failed: BAP outstanding requests");
                pause_if_requested(pauseOnExit);
                return 1;
            }
            checkpoint("[+] Patch done: BAP outstanding requests");
        }
        else {
            checkpoint("[*] Skipping BAP outstanding requests");
        }

        checkpoint("[+] All patches applied.");
        pause_if_requested(pauseOnExit);
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "[!] " << ex.what() << "\n";
        checkpoint(std::string("[!] std::exception: ") + ex.what());
        pause_if_requested(pauseOnExit);
        return 1;
    }
}
