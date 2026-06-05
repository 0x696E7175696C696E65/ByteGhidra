#include <ntifs.h>
#include <windef.h>

#ifndef VIRTUALIZER_START
#define VIRTUALIZER_START
#define VIRTUALIZER_END
#define VIRTUALIZER_STR_ENCRYPT_START
#define VIRTUALIZER_STR_ENCRYPT_END
#endif

#define DRIVER_NT_DEVICE_PATH_W L"\\Device\\D2PatchDriver"
#define DRIVER_DOS_DEVICES_PATH_W L"\\DosDevices\\D2PatchDriver"

UNICODE_STRING name, link;

typedef struct _SYSTEM_BIGPOOL_ENTRY {
	PVOID VirtualAddress;
	ULONG_PTR NonPaged : 1;
	ULONG_PTR SizeInBytes;
	UCHAR Tag[4];
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1]; // Flexible array member, adjust as needed
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBigPoolInformation = 0x42,
} SYSTEM_INFORMATION_CLASS;

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS FromProcess, PVOID FromAddress, PEPROCESS ToProcess,
	PVOID ToAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

#define code_rw CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1645, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_ba CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1646, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_get_guarded_region CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1647, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_handshake CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1648, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_alloc_vm CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1649, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_security 0x85b3b69

static ULONGLONG g_session_token = 0;
static INT32 g_session_client_pid = 0;
#define win_1803 17134
#define win_1809 17763
#define win_1903 18362
#define win_1909 18363
#define win_2004 19041
#define win_20H2 19569
#define win_21H1 20180

#define PAGE_OFFSET_SIZE 12
static const UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull;

typedef struct _handshake_io {
	INT32 magic;
	INT32 client_pid;
	ULONGLONG session_token;
} handshake_io, * phandshake_io;

typedef struct _rw {
	INT32 security;
	INT32 process_id;
	ULONGLONG address;
	ULONGLONG buffer;
	ULONGLONG size;
	BOOLEAN write;
	ULONGLONG session_token;
} rw, * prw;

typedef struct _ba {
	INT32 security;
	INT32 process_id;
	ULONGLONG* address;
	ULONGLONG session_token;
} ba, * pba;

typedef struct _ga {
	INT32 security;
	ULONGLONG* address;
	ULONGLONG session_token;
} ga, * pga;

typedef struct _alloc_vm {
	INT32 security;
	INT32 process_id;
	ULONGLONG size;
	ULONGLONG address;
	ULONGLONG session_token;
} alloc_vm, * palloc_vm;

static NTSTATUS validate_ioctl_session(PIRP irp, ULONGLONG token)
{
	if (g_session_token == 0 || token != g_session_token)
		return STATUS_ACCESS_DENIED;

	PEPROCESS requestor = IoGetRequestorProcess(irp);
	if (!requestor)
		return STATUS_ACCESS_DENIED;

	HANDLE req_pid = PsGetProcessId(requestor);
	if ((INT32)(LONG_PTR)req_pid != g_session_client_pid)
		return STATUS_ACCESS_DENIED;

	return STATUS_SUCCESS;
}


NTSTATUS read(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read) {
	VIRTUALIZER_START
	MM_COPY_ADDRESS to_read = { 0 };
	to_read.PhysicalAddress.QuadPart = (LONGLONG)target_address;

	NTSTATUS status = MmCopyMemory(buffer, to_read, size, MM_COPY_MEMORY_PHYSICAL, bytes_read);
	VIRTUALIZER_END

	return status;
}

NTSTATUS write(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read)
{
	if (!target_address)
	{
		return STATUS_UNSUCCESSFUL;
	}

	VIRTUALIZER_START
	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = LONGLONG(target_address);

	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, size, PAGE_READWRITE);
	NTSTATUS result = STATUS_SUCCESS;

	if (!pmapped_mem)
	{
		result = STATUS_UNSUCCESSFUL;
	}
	else
	{
		memcpy(pmapped_mem, buffer, size);
		*bytes_read = size;
		MmUnmapIoSpace(pmapped_mem, size);
	}
	VIRTUALIZER_END

	return result;
}

INT32 get_winver() {
	VIRTUALIZER_START
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);
	INT32 result = 0x0388;
	switch (ver.dwBuildNumber)
	{
	case win_1803:
		result = 0x0278;
		break;
	case win_1809:
		result = 0x0278;
		break;
	case win_1903:
		result = 0x0280;
		break;
	case win_1909:
		result = 0x0280;
		break;
	case win_2004:
		result = 0x0388;
		break;
	case win_20H2:
		result = 0x0388;
		break;
	case win_21H1:
		result = 0x0388;
		break;
	default:
		result = 0x0388;
		break;
	}
	VIRTUALIZER_END
	return result;
}

UINT64 get_process_cr3(const PEPROCESS pProcess) {
	VIRTUALIZER_START
	PUCHAR process = (PUCHAR)pProcess;
	ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);
	ULONG_PTR result = process_dirbase;

	if (process_dirbase == 0) {
		INT32 UserDirOffset = get_winver();
		result = *(PULONG_PTR)(process + UserDirOffset);
	}
	VIRTUALIZER_END

	return result;
}

UINT64 translate_linear(UINT64 directoryTableBase, UINT64 virtualAddress) {
	VIRTUALIZER_START
	directoryTableBase &= ~0xf;

	UINT64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
	UINT64 pte = ((virtualAddress >> 12) & (0x1ffll));
	UINT64 pt = ((virtualAddress >> 21) & (0x1ffll));
	UINT64 pd = ((virtualAddress >> 30) & (0x1ffll));
	UINT64 pdp = ((virtualAddress >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	UINT64 pdpe = 0;
	read(PVOID(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
	UINT64 result = 0;

	if (~pdpe & 1) {
		result = 0;
	}
	else {
		UINT64 pde = 0;
		read(PVOID((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
		if (~pde & 1) {
			result = 0;
		}
		else if (pde & 0x80) {
			result = (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));
		}
		else {
			UINT64 pteAddr = 0;
			read(PVOID((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
			if (~pteAddr & 1) {
				result = 0;
			}
			else if (pteAddr & 0x80) {
				result = (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));
			}
			else {
				virtualAddress = 0;
				read(PVOID((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize);
				virtualAddress &= PMASK;

				if (!virtualAddress) {
					result = 0;
				}
				else {
					result = virtualAddress + pageOffset;
				}
			}
		}
	}
	VIRTUALIZER_END
	return result;
}

ULONG64 find_min(INT32 g, SIZE_T f) {
	VIRTUALIZER_START
	INT32 h = (INT32)f;
	ULONG64 result = 0;
	result = (((g) < (h)) ? (g) : (h));
	VIRTUALIZER_END
	return result;
}

NTSTATUS frw(PIRP irp, prw x) {
	if (x->security != code_security) {
		return STATUS_UNSUCCESSFUL;
	}

	if (g_session_token == 0 || x->session_token != g_session_token) {
		return STATUS_ACCESS_DENIED;
	}

	if (!x->process_id) {
		return STATUS_UNSUCCESSFUL;
	}

	VIRTUALIZER_START
	PEPROCESS process = NULL;
	NTSTATUS result = STATUS_UNSUCCESSFUL;
	NTSTATUS lookup_status = PsLookupProcessByProcessId((HANDLE)x->process_id, &process);

	if (!NT_SUCCESS(lookup_status) || !process) {
		VIRTUALIZER_END
		return lookup_status;
	}

	PEPROCESS requestor = IoGetRequestorProcess(irp);
	if (!requestor) {
		ObDereferenceObject(process);
		VIRTUALIZER_END
		return STATUS_ACCESS_DENIED;
	}

	SIZE_T copied = 0;
	if (x->write) {
		result = MmCopyVirtualMemory(requestor, (PVOID)(ULONG_PTR)x->buffer,
			process, (PVOID)(ULONG_PTR)x->address, (SIZE_T)x->size, KernelMode, &copied);
	}
	else {
		result = MmCopyVirtualMemory(process, (PVOID)(ULONG_PTR)x->address,
			requestor, (PVOID)(ULONG_PTR)x->buffer, (SIZE_T)x->size, KernelMode, &copied);
	}

	if (NT_SUCCESS(result) && copied == (SIZE_T)x->size) {
		ObDereferenceObject(process);
		VIRTUALIZER_END
		return STATUS_SUCCESS;
	}

	if (process) {
		ULONGLONG process_base = get_process_cr3(process);
		ObDereferenceObject(process);

		SIZE_T this_offset = NULL;
		SIZE_T total_size = x->size;

		INT64 physical_address = translate_linear(process_base, (ULONG64)x->address + this_offset);
		if (physical_address) {
			ULONG64 final_size = find_min(PAGE_SIZE - (physical_address & 0xFFF), total_size);
			SIZE_T bytes_trough = NULL;

			if (x->write) {
				write(PVOID(physical_address), (PVOID)((ULONG64)x->buffer + this_offset), final_size, &bytes_trough);
			}
			else {
				read(PVOID(physical_address), (PVOID)((ULONG64)x->buffer + this_offset), final_size, &bytes_trough);
			}

			result = STATUS_SUCCESS;
		}
	}
	VIRTUALIZER_END

	return result;
}

NTSTATUS fba(pba x) {
	if (x->security != code_security) {
		return STATUS_UNSUCCESSFUL;
	}

	if (g_session_token == 0 || x->session_token != g_session_token) {
		return STATUS_ACCESS_DENIED;
	}

	if (!x->process_id) {
		return STATUS_UNSUCCESSFUL;
	}

	VIRTUALIZER_START
	PEPROCESS process = NULL;
	PsLookupProcessByProcessId((HANDLE)x->process_id, &process);
	NTSTATUS result = STATUS_UNSUCCESSFUL;

	if (process) {
		ULONGLONG image_base = (ULONGLONG)PsGetProcessSectionBaseAddress(process);

		if (image_base) {
			RtlCopyMemory(x->address, &image_base, sizeof(image_base));
			result = STATUS_SUCCESS;
		}

		ObDereferenceObject(process);
	}
	VIRTUALIZER_END

	return result;
}

NTSTATUS falloc(palloc_vm x) {
	if (x->security != code_security) {
		return STATUS_UNSUCCESSFUL;
	}

	if (g_session_token == 0 || x->session_token != g_session_token) {
		return STATUS_ACCESS_DENIED;
	}

	if (!x->process_id || !x->size) {
		return STATUS_UNSUCCESSFUL;
	}

	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)x->process_id, &process);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	KAPC_STATE apc_state;
	PVOID base = NULL;
	SIZE_T region_size = (SIZE_T)x->size;

	KeStackAttachProcess(process, &apc_state);
	status = ZwAllocateVirtualMemory(
		ZwCurrentProcess(),
		&base,
		0,
		&region_size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	KeUnstackDetachProcess(&apc_state);

	ObDereferenceObject(process);

	if (NT_SUCCESS(status)) {
		x->address = (ULONGLONG)base;
		x->size = (ULONGLONG)region_size;
	}

	return status;
}

NTSTATUS fget_guarded_region(pga x) {
	if (x->security != code_security) {
		return STATUS_UNSUCCESSFUL;
	}

	if (g_session_token == 0 || x->session_token != g_session_token) {
		return STATUS_ACCESS_DENIED;
	}

	// String encryption must be outside virtualization block to avoid nesting
	VIRTUALIZER_STR_ENCRYPT_START
	UCHAR expectedTag[] = "TnoC";
	VIRTUALIZER_STR_ENCRYPT_END

	VIRTUALIZER_START
	ULONG infoLen = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemBigPoolInformation, &infoLen, 0, &infoLen);
	PSYSTEM_BIGPOOL_INFORMATION pPoolInfo = 0;
	NTSTATUS result = STATUS_SUCCESS;

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (pPoolInfo)
			ExFreePool(pPoolInfo);

		pPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePool(NonPagedPool, infoLen);
		status = ZwQuerySystemInformation(SystemBigPoolInformation, pPoolInfo, infoLen, &infoLen);
	}

	if (pPoolInfo)
	{
		for (unsigned int i = 0; i < pPoolInfo->Count; i++)
		{
			SYSTEM_BIGPOOL_ENTRY* Entry = &pPoolInfo->AllocatedInfo[i];
			PVOID VirtualAddress;
			VirtualAddress = (PVOID)((uintptr_t)Entry->VirtualAddress & ~1ull);
			SIZE_T SizeInBytes = Entry->SizeInBytes;
			BOOLEAN NonPaged = Entry->NonPaged;

			if (Entry->NonPaged && Entry->SizeInBytes == 0x200000) {
				if (memcmp(Entry->Tag, expectedTag, sizeof(expectedTag)) == 0) {
					RtlCopyMemory((void*)x->address, &Entry->VirtualAddress, sizeof(Entry->VirtualAddress));
					result = STATUS_SUCCESS;
					ExFreePool(pPoolInfo);
					pPoolInfo = NULL;
					break;
				}
			}

		}

		if (pPoolInfo)
			ExFreePool(pPoolInfo);
	}
	VIRTUALIZER_END

	return result;
}

NTSTATUS io_controller(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	NTSTATUS status = { };
	ULONG bytes = { };
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

	if (code == code_handshake) {
		ULONG out_len = stack->Parameters.DeviceIoControl.OutputBufferLength;
		if (size < sizeof(handshake_io) || out_len < sizeof(handshake_io)) {
			status = STATUS_BUFFER_TOO_SMALL;
			bytes = 0;
		}
		else {
			phandshake_io hs = (phandshake_io)(irp->AssociatedIrp.SystemBuffer);
			PEPROCESS requestor = IoGetRequestorProcess(irp);
			if (!requestor) {
				status = STATUS_ACCESS_DENIED;
				bytes = 0;
			}
			else {
				HANDLE req_pid = PsGetProcessId(requestor);

				if (hs->magic != code_security || hs->client_pid != (INT32)(LONG_PTR)req_pid) {
					status = STATUS_ACCESS_DENIED;
					bytes = 0;
				}
				else {
					LARGE_INTEGER perf = KeQueryPerformanceCounter(NULL);
					ULONGLONG tok = perf.QuadPart ^ 0x9E3779B97F4A7C15ULL ^ (ULONGLONG)(ULONG_PTR)req_pid;
					if (tok == 0)
						tok = 1;
					g_session_token = tok;
					g_session_client_pid = (INT32)(LONG_PTR)req_pid;
					hs->session_token = g_session_token;
					status = STATUS_SUCCESS;
					bytes = sizeof(handshake_io);
				}
			}
		}
	}
	else if (code == code_rw) {
		if (size == sizeof(rw)) {
			prw req = (prw)(irp->AssociatedIrp.SystemBuffer);

			status = validate_ioctl_session(irp, req->session_token);
			if (NT_SUCCESS(status))
				status = frw(irp, req);
			bytes = sizeof(rw);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}
	else if (code == code_ba) {
		if (size == sizeof(ba)) {
			pba req = (pba)(irp->AssociatedIrp.SystemBuffer);

			status = validate_ioctl_session(irp, req->session_token);
			if (NT_SUCCESS(status))
				status = fba(req);
			bytes = sizeof(ba);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}
	else if (code == code_get_guarded_region) {
		if (size == sizeof(ga)) {
			pga req = (pga)(irp->AssociatedIrp.SystemBuffer);

			status = validate_ioctl_session(irp, req->session_token);
			if (NT_SUCCESS(status))
				status = fget_guarded_region(req);
			bytes = sizeof(ga);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}
	else if (code == code_alloc_vm) {
		if (size == sizeof(alloc_vm)) {
			palloc_vm req = (palloc_vm)(irp->AssociatedIrp.SystemBuffer);

			status = validate_ioctl_session(irp, req->session_token);
			if (NT_SUCCESS(status))
				status = falloc(req);
			bytes = sizeof(alloc_vm);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}

	// Handle unsupported IOCTLs
	if (status == 0 && bytes == 0) {
		status = STATUS_INVALID_DEVICE_REQUEST;
		bytes = 0;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytes;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS unsupported_dispatch(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return irp->IoStatus.Status;
}

NTSTATUS dispatch_handler(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	switch (stack->MajorFunction) {
	case IRP_MJ_CREATE:
		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;
		break;
	case IRP_MJ_CLOSE:
		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;
		break;
	default:
		irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
		irp->IoStatus.Information = 0;
		break;
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

void unload_drv(PDRIVER_OBJECT drv_obj) {
	NTSTATUS status = { };

	status = IoDeleteSymbolicLink(&link);

	if (!NT_SUCCESS(status))
		return;

	IoDeleteDevice(drv_obj->DeviceObject);
}

NTSTATUS initialize_driver(PDRIVER_OBJECT drv_obj, PUNICODE_STRING path) {
	UNREFERENCED_PARAMETER(path);

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT device_obj = NULL;

	RtlInitUnicodeString(&name, DRIVER_NT_DEVICE_PATH_W);
	RtlInitUnicodeString(&link, DRIVER_DOS_DEVICES_PATH_W);

	// Create the device
	status = IoCreateDevice(drv_obj, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_obj);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// Create a symbolic link
	status = IoCreateSymbolicLink(&link, &name);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(device_obj);
		return status;
	}

	// Set up IRP dispatch functions
	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		drv_obj->MajorFunction[i] = &unsupported_dispatch;
	}

	drv_obj->MajorFunction[IRP_MJ_CREATE] = &dispatch_handler;
	drv_obj->MajorFunction[IRP_MJ_CLOSE] = &dispatch_handler;
	drv_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &io_controller;
	drv_obj->DriverUnload = &unload_drv;

	// Configure device flags
	device_obj->Flags |= DO_BUFFERED_IO;
	device_obj->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}

// Manual-map loaders may invoke DriverEntry via a syscall trampoline with a bogus non-null "DriverObject".
#if defined(_WIN64)
static BOOLEAN driver_object_pointer_plausible(PDRIVER_OBJECT drv)
{
	if (!drv)
		return FALSE;
	const ULONG_PTR p = reinterpret_cast<ULONG_PTR>(drv);
	return (p >= 0xFFFF800000000000ULL);
}
#else
static BOOLEAN driver_object_pointer_plausible(PDRIVER_OBJECT drv)
{
	return drv != NULL;
}
#endif

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	if (!driver_object_pointer_plausible(DriverObject))
		return IoCreateDriver(NULL, &initialize_driver);

	return initialize_driver(DriverObject, RegistryPath);
}
