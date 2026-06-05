"""
Memory Patcher — Bypass Auth + DLC Checks at Runtime
=====================================================
Patches the running Destiny 2 process to:
  1. Mock the user session (fake credential token)
  2. Disable all kill switches (open all feature gates)
  3. Bypass XStore COM requirements (set XGameRuntime ready flag)
  4. Set DLC ownership flags (all DLCs owned)

Uses Windows ReadProcessMemory/WriteProcessMemory via ctypes.
Does not modify DNS, hosts, certificates, or netsh portproxy rules.
Run AFTER launching Destiny 2 and reaching the login screen.

Addresses are RVA-based — auto-calculated from actual load address.

RVA VERIFICATION STATUS (confirmed via Ghidra MCP read-only analysis):
  g_user_session        0x1d72f90  ✅ 65+ xrefs from 0x7ff70ff0xxxx cluster
  g_killswitch_registry 0x1fa33c0  ✅ 19 xrefs including write at 7ff710a82420
  xgameruntime_ready    0x2f235a8  ✅ 5 xrefs; FUN_7ff7116f41fc sets +8 = 1 on init
  license_suppression   0x1fcf410  ✅ used by is_license_check_enabled(ptr, 0x12)
  g_dlc_state           0x1fcf428  ✅ used by dlc_entitlement_response_callback

LICENSE SUPPRESSION LOGIC (confirmed via is_license_check_enabled @ 7ff710ef3790):
  is_license_check_enabled(param_1, index):
    if param_1 != NULL and valid_index(index) and *param_1 != 0:
        return 0   ← checks DISABLED → game uses fake entitlement 0xe0200001 (all DLC)
    return 1       ← checks ENABLED  → game sends BAP request to verify DLC
  Therefore:
    write 1 → *param_1 != 0 → returns 0 → checks DISABLED → all DLC granted ✅
    write 0 → *param_1 == 0 → returns 1 → checks ENABLED  → DLC verification runs ❌
"""

import ctypes
import ctypes.wintypes as W
import os
import subprocess
import struct
import sys
import time
import logging

try:
    import psutil
except ModuleNotFoundError:
    psutil = None

log = logging.getLogger("Patcher")

CPP_PATCHER_REL = os.path.join(
    "driver_patcher", "bin", "x64", "Release", "d2_driver_patcher.exe")
CPP_PATCHER_LEGACY_REL = os.path.join(
    "driver_patcher", "bin", "x64", "Release", "d2_driver_patcher_logged.exe")

def run_cpp_patcher():
    patch_dir = os.path.dirname(__file__)
    exe_path = os.path.join(patch_dir, CPP_PATCHER_REL)
    if not os.path.exists(exe_path):
        exe_path = os.path.join(patch_dir, CPP_PATCHER_LEGACY_REL)
    if not os.path.exists(exe_path):
        log.error("Driver-backed patcher exe not found: {}".format(exe_path))
        log.error("Build it with: MSBuild patch\\driver_patcher\\d2_driver_patcher.vcxproj /p:Configuration=Release /p:Platform=x64")
        return False

    log.info("Launching driver-backed C++ patcher: {}".format(exe_path))
    completed = subprocess.run([exe_path] + sys.argv[1:], cwd=patch_dir)
    return completed.returncode == 0

# ── RVAs from RE work ─────────────────────────────────────────────────────────
RVA_G_USER_SESSION          = 0x7ff712c72f90 - 0x7ff70fb00000  # 0x1d72f90
RVA_G_KILLSWITCH_REGISTRY   = 0x7ff712aa33c0 - 0x7ff70fb00000  # 0x1fa33c0
RVA_LICENSE_SUPPRESSION     = 0x7ff712acf410 - 0x7ff70fb00000  # 0x1fcf410
RVA_XGAMERUNTIME_READY      = 0x7ff713a235a8 - 0x7ff70fb00000  # 0x2f235a8
RVA_G_DLC_STATE             = 0x7ff712acf428 - 0x7ff70fb00000  # 0x1fcf428
RVA_BAP_OUTSTANDING_REQ     = 0x7ff712a5bb8c - 0x7ff70fb00000  # 0x1f5bb8c

# Kill switch registry: condition values at +0x19808, 512 uint32s, default=4
# Set all to 5 (> default threshold of 4 = active, but threshold check is <= so 5 = inactive)
KS_TABLE_OFFSET             = 0x19808
KS_TABLE_COUNT              = 512

# User session offsets (from g_user_session)
SESSION_USER_ID_OFFSET      = 0x5c0   # int32: -1 = no user
SESSION_TOKEN_OFFSET        = 0x108   # ptr: credential token
SESSION_SESSION_ID_OFFSET   = 0x138   # int32: must match USER_ID

FAKE_USER_ID    = 1
FAKE_SESSION_ID = 1
FAKE_TOKEN      = b"D2PrivateServerToken_v1\x00"

# ── Win32 API ─────────────────────────────────────────────────────────────────
kernel32 = ctypes.windll.kernel32

PROCESS_ALL_ACCESS    = 0x1F0FFF
TH32CS_SNAPPROCESS    = 0x00000002

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              W.DWORD),
        ("cntUsage",            W.DWORD),
        ("th32ProcessID",       W.DWORD),
        ("th32DefaultHeapID",   ctypes.POINTER(W.ULONG)),
        ("th32ModuleID",        W.DWORD),
        ("cntThreads",          W.DWORD),
        ("th32ParentProcessID", W.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             W.DWORD),
        ("szExeFile",           ctypes.c_char * 260),
    ]

def find_process(name):
    if psutil is None:
        log.error("psutil is required only for the legacy Python patcher path.")
        return None
    for proc in psutil.process_iter(["pid","name"]):
        if name.lower() in proc.info["name"].lower():
            return proc.info["pid"]
    return None

def get_module_base(pid, module_name="destiny2.exe"):
    if psutil is None:
        log.error("psutil is required only for the legacy Python patcher path.")
        return None
    for proc in psutil.process_iter(["pid","name"]):
        if proc.info["pid"] == pid:
            try:
                for m in proc.memory_maps():
                    if module_name.lower() in m.path.lower():
                        return int(m.addr.split("-")[0], 16)
            except Exception:
                pass
    return None

def read_mem(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    read = W.SIZE_T(0)
    kernel32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(read))
    return buf.raw[:read.value]

def write_mem(handle, addr, data):
    written = W.SIZE_T(0)
    buf = ctypes.create_string_buffer(data)
    return kernel32.WriteProcessMemory(
        handle, ctypes.c_void_p(addr), buf, len(data), ctypes.byref(written))

def alloc_mem(handle, size):
    MEM_COMMIT   = 0x1000
    MEM_RESERVE  = 0x2000
    PAGE_READWRITE = 0x04
    return kernel32.VirtualAllocEx(
        handle, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

# ── Patch functions ───────────────────────────────────────────────────────────

def patch_user_session(handle, base):
    """Write a fake user session so get_active_user_credential() succeeds."""
    session_addr = base + RVA_G_USER_SESSION

    # Allocate space for the fake token string
    token_addr = alloc_mem(handle, 64)
    if not token_addr:
        log.error("Failed to allocate token memory")
        return False

    # Write fake token string
    write_mem(handle, token_addr, FAKE_TOKEN)

    # Write user session fields
    # +0x5c0: user_id = 1
    write_mem(handle, session_addr + SESSION_USER_ID_OFFSET,
              struct.pack("<i", FAKE_USER_ID))
    # +0x138: session_id = 1 (must match user_id)
    write_mem(handle, session_addr + SESSION_SESSION_ID_OFFSET,
              struct.pack("<i", FAKE_SESSION_ID))
    # +0x108: token pointer
    write_mem(handle, session_addr + SESSION_TOKEN_OFFSET,
              struct.pack("<Q", token_addr))

    log.info("  [+] User session patched (user_id={}, token @ 0x{:x})".format(
        FAKE_USER_ID, token_addr))
    return True

def patch_kill_switches(handle, base):
    """Set all 512 kill switch condition values to 5 (disables all gates)."""
    ks_addr = base + RVA_G_KILLSWITCH_REGISTRY

    # Read current registry pointer
    reg_ptr_data = read_mem(handle, ks_addr, 8)
    if len(reg_ptr_data) < 8:
        log.error("  [!] Could not read kill switch registry pointer")
        return False

    reg_ptr = struct.unpack("<Q", reg_ptr_data)[0]
    if not reg_ptr:
        log.error("  [!] Kill switch registry not initialized yet")
        return False

    # Table is at reg_ptr + 0x19808
    table_addr = reg_ptr + KS_TABLE_OFFSET
    # Write 512 uint32 values of 5
    table_data = struct.pack("<{}I".format(KS_TABLE_COUNT), *([5] * KS_TABLE_COUNT))
    if write_mem(handle, table_addr, table_data):
        log.info("  [+] Kill switches patched ({} gates disabled)".format(KS_TABLE_COUNT))
    else:
        log.warning("  [!] Kill switch patch may have failed")
    return True

def patch_xgameruntime(handle, base):
    """Set XGameRuntime ready flag so xstore_com_acquire_interface skips availability check."""
    addr = base + RVA_XGAMERUNTIME_READY
    write_mem(handle, addr, struct.pack("<B", 1))
    log.info("  [+] XGameRuntime ready flag set")

    # Disable license check: write 1 so is_license_check_enabled() returns 0
    # (see is_license_check_enabled @ 7ff710ef3790 — non-zero = check disabled = DLC granted)
    # Writing 0 is WRONG — it enables checks. Writing 1 disables them.
    supp_addr = base + RVA_LICENSE_SUPPRESSION
    write_mem(handle, supp_addr, struct.pack("<B", 1))  # 1 = license check DISABLED
    log.info("  [+] License check disabled (fake entitlement 0xe0200001 active)")
    return True

def patch_outstanding_requests(handle, base):
    """Zero the outstanding request counter so the system doesn't wait."""
    addr = base + RVA_BAP_OUTSTANDING_REQ
    write_mem(handle, addr, struct.pack("<I", 0))
    log.info("  [+] BAP outstanding request counter zeroed")
    return True

# ── Main patcher ──────────────────────────────────────────────────────────────

def patch_game():
    log.info("=" * 55)
    log.info("  DESTINY 2 MEMORY PATCHER")
    log.info("=" * 55)
    log.info("")
    log.info("Searching for destiny2.exe...")

    pid = find_process("destiny2.exe")
    if not pid:
        log.error("destiny2.exe not found. Launch the game first.")
        return False

    log.info("Found PID: {}".format(pid))

    base = get_module_base(pid)
    if not base:
        log.error("Could not find module base. Try running as Administrator.")
        return False

    log.info("Module base: 0x{:x}".format(base))
    log.info("Waiting for game to reach login screen (10s)...")
    time.sleep(10)

    handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        log.error("OpenProcess failed. Run as Administrator.")
        return False

    log.info("")
    log.info("Applying patches:")

    try:
        patch_xgameruntime(handle, base)
        patch_kill_switches(handle, base)
        patch_user_session(handle, base)
        patch_outstanding_requests(handle, base)
    finally:
        kernel32.CloseHandle(handle)

    log.info("")
    log.info("All patches applied.")
    log.info("The game should now authenticate against your private server.")
    log.info("")
    log.info("TIER 1 (Solo): You can now play without Bungie authentication.")
    log.info("TIER 2 (Multi): Start server.py --tier2 before launching activities.")
    return True

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='[%(asctime)s] %(name)s: %(message)s')
    exit_code = 0
    try:
        if not run_cpp_patcher():
            exit_code = 1
    finally:
        try:
            input("\nPress Enter to exit...")
        except EOFError:
            pass

    sys.exit(exit_code)
