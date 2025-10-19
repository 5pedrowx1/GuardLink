#define IOCTL_BASE 0x8000

#define CTL_CODE(DeviceType, Function, Method, Access) \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)

#define FILE_DEVICE_UNKNOWN 0x00000022
#define METHOD_BUFFERED 0
#define FILE_ANY_ACCESS 0

#define IOCTL_SET_TARGET       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENABLE_MONITOR   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_MEMORY      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INSTALL_HOOK     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_HOOK      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_PROCESS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT_PROCESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

#include "shared_defs.h"
#include <ntstrsafe.h>
// ==================== CONFIGURAÇÃO ====================

#define DEVICE_NAME L"\\Device\\{A7C5E891-2D3F-4B5A-9E8C-1F6D3A7B9C4E}"
#define DOS_NAME L"\\DosDevices\\Global\\GuardLink"

#define TAG_POOL 'LdrG'
#define TAG_HOOK 'kooH'
#define TAG_MODULE 'doM'

#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE 0x0020
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_QUERY_INFORMATION 0x0400
#define PROCESS_SUSPEND_RESUME 0x0800
#define PROCESS_TERMINATE 0x0001

#define DbgLog(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Drv] " fmt, __VA_ARGS__)

// ==================== ESTRUTURAS ====================

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];
    PKPROCESS Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;
} KAPC_STATE, * PKAPC_STATE, * PRKAPC_STATE;

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} MY_PEB_LDR_DATA, * PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PMY_PEB_LDR_DATA Ldr;
} MY_PEB, * PMY_PEB;

typedef struct _FUNCTION_HOOK {
    LIST_ENTRY ListEntry;
    PVOID TargetAddress;
    UCHAR OriginalBytes[16];
    ULONG HookSize;
    ULONG Flags;
} FUNCTION_HOOK, * PFUNCTION_HOOK;

typedef struct _PROTECTED_PROCESS {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    PEPROCESS Process;
    LIST_ENTRY HookList;
    BOOLEAN IsHidden;
    PLIST_ENTRY OriginalFlink;
    PLIST_ENTRY OriginalBlink;
} PROTECTED_PROCESS, * PPROTECTED_PROCESS;

typedef struct _DRIVER_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    LIST_ENTRY ProcessList;
    KSPIN_LOCK ProcessListLock;
    WCHAR TargetProcessName[260];
    BOOLEAN MonitoringEnabled;
    PVOID CallbackHandle;
} DRIVER_CONTEXT, * PDRIVER_CONTEXT;

PDRIVER_CONTEXT g_Context = NULL;

// ==================== IMPORTS ====================

NTKERNELAPI VOID KeStackAttachProcess(_In_ PKPROCESS Process, _Out_ PRKAPC_STATE ApcState);
NTKERNELAPI VOID KeUnstackDetachProcess(_In_ PRKAPC_STATE ApcState);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(IN HANDLE ProcessId, OUT PEPROCESS* Process);
NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI PCHAR PsGetProcessImageFileName(IN PEPROCESS Process);
NTKERNELAPI HANDLE PsGetProcessId(IN PEPROCESS Process);
extern POBJECT_TYPE* PsProcessType;

// ==================== UTILIDADES ====================

PPROTECTED_PROCESS FindProtectedProcess(HANDLE ProcessId) {
    KIRQL oldIrql;
    PPROTECTED_PROCESS result = NULL;

    KeAcquireSpinLock(&g_Context->ProcessListLock, &oldIrql);

    for (PLIST_ENTRY entry = g_Context->ProcessList.Flink;
        entry != &g_Context->ProcessList;
        entry = entry->Flink) {
        PPROTECTED_PROCESS proc = CONTAINING_RECORD(entry, PROTECTED_PROCESS, ListEntry);
        if (proc->ProcessId == ProcessId) {
            result = proc;
            break;
        }
    }

    KeReleaseSpinLock(&g_Context->ProcessListLock, oldIrql);
    return result;
}

// ==================== MEMORY OPERATIONS ====================

NTSTATUS ReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PVOID Buffer,
    _In_ SIZE_T Size)
{
    PEPROCESS process;
    KAPC_STATE apcState;
    NTSTATUS status;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    KeStackAttachProcess((PKPROCESS)process, &apcState);

    __try {
        ProbeForRead(Address, Size, 1);
        RtlCopyMemory(Buffer, Address, Size);
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}

NTSTATUS WriteProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size)
{
    PEPROCESS process;
    KAPC_STATE apcState;
    NTSTATUS status;
    PMDL mdl = NULL;
    PVOID mappedAddress = NULL;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    KeStackAttachProcess((PKPROCESS)process, &apcState);

    __try {
        mdl = IoAllocateMdl(Address, (ULONG)Size, FALSE, FALSE, NULL);
        if (!mdl) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        mappedAddress = MmMapLockedPagesSpecifyCache(
            mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

        if (!mappedAddress) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        RtlCopyMemory(mappedAddress, Buffer, Size);
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (mappedAddress && mdl) MmUnmapLockedPages(mappedAddress, mdl);
    if (mdl) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}

// ==================== MODULE ENUMERATION ====================

NTSTATUS GetModuleBase(
    _In_ HANDLE ProcessId,
    _In_ PWCHAR ModuleName,
    _Out_ PVOID* BaseAddress,
    _Out_ PULONG Size)
{
    PEPROCESS process;
    PPEB peb;
    PMY_PEB_LDR_DATA ldrData;
    PLIST_ENTRY listHead, listEntry;
    KAPC_STATE apcState;
    NTSTATUS status = STATUS_NOT_FOUND;

    *BaseAddress = NULL;
    *Size = 0;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    peb = PsGetProcessPeb(process);
    if (!peb) {
        ObDereferenceObject(process);
        return STATUS_UNSUCCESSFUL;
    }

    KeStackAttachProcess((PKPROCESS)process, &apcState);

    __try {
        ProbeForRead(peb, sizeof(MY_PEB), 1);
        ldrData = ((PMY_PEB)peb)->Ldr;

        if (!ldrData) {
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        ProbeForRead(ldrData, sizeof(MY_PEB_LDR_DATA), 1);
        listHead = &ldrData->InLoadOrderModuleList;
        listEntry = listHead->Flink;

        while (listEntry != listHead) {
            PMY_LDR_DATA_TABLE_ENTRY ldrEntry =
                CONTAINING_RECORD(listEntry, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            ProbeForRead(ldrEntry, sizeof(MY_LDR_DATA_TABLE_ENTRY), 1);

            if (ldrEntry->BaseDllName.Buffer && ldrEntry->BaseDllName.Length > 0) {
                if (_wcsicmp(ldrEntry->BaseDllName.Buffer, ModuleName) == 0) {
                    *BaseAddress = ldrEntry->DllBase;
                    *Size = ldrEntry->SizeOfImage;
                    status = STATUS_SUCCESS;
                    __leave;
                }
            }

            listEntry = listEntry->Flink;
            if (listEntry == listHead) break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}

// ==================== HOOK MANAGEMENT ====================

NTSTATUS InstallInlineHook(
    _In_ HANDLE ProcessId,
    _In_ PVOID TargetAddress,
    _In_ PUCHAR HookCode,
    _In_ ULONG HookSize)
{
    if (HookSize > 16 || HookSize < 5) return STATUS_INVALID_PARAMETER;

    PPROTECTED_PROCESS protectedProc = FindProtectedProcess(ProcessId);
    if (!protectedProc) return STATUS_NOT_FOUND;

    UCHAR originalBytes[16];
    NTSTATUS status = ReadProcessMemory(ProcessId, TargetAddress, originalBytes, HookSize);
    if (!NT_SUCCESS(status)) return status;

    status = WriteProcessMemory(ProcessId, TargetAddress, HookCode, HookSize);
    if (!NT_SUCCESS(status)) return status;

    PFUNCTION_HOOK hook = (PFUNCTION_HOOK)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(FUNCTION_HOOK), TAG_HOOK);

    if (!hook) {
        WriteProcessMemory(ProcessId, TargetAddress, originalBytes, HookSize);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    hook->TargetAddress = TargetAddress;
    RtlCopyMemory(hook->OriginalBytes, originalBytes, HookSize);
    hook->HookSize = HookSize;
    hook->Flags = 0x01;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Context->ProcessListLock, &oldIrql);
    InsertTailList(&protectedProc->HookList, &hook->ListEntry);
    KeReleaseSpinLock(&g_Context->ProcessListLock, oldIrql);

    DbgLog("Hook installed at %p\n", TargetAddress);
    return STATUS_SUCCESS;
}

NTSTATUS RemoveHook(_In_ HANDLE ProcessId, _In_ PVOID TargetAddress) {
    PPROTECTED_PROCESS protectedProc = FindProtectedProcess(ProcessId);
    if (!protectedProc) return STATUS_NOT_FOUND;

    KIRQL oldIrql;
    PFUNCTION_HOOK hookToRemove = NULL;

    KeAcquireSpinLock(&g_Context->ProcessListLock, &oldIrql);

    for (PLIST_ENTRY entry = protectedProc->HookList.Flink;
        entry != &protectedProc->HookList;
        entry = entry->Flink) {
        PFUNCTION_HOOK hook = CONTAINING_RECORD(entry, FUNCTION_HOOK, ListEntry);
        if (hook->TargetAddress == TargetAddress) {
            RemoveEntryList(entry);
            hookToRemove = hook;
            break;
        }
    }

    KeReleaseSpinLock(&g_Context->ProcessListLock, oldIrql);

    if (!hookToRemove) return STATUS_NOT_FOUND;

    NTSTATUS status = WriteProcessMemory(
        ProcessId, hookToRemove->TargetAddress,
        hookToRemove->OriginalBytes, hookToRemove->HookSize);

    ExFreePoolWithTag(hookToRemove, TAG_HOOK);
    return status;
}

// ==================== PROCESS HIDING ====================

NTSTATUS HideProcessFromList(_In_ HANDLE ProcessId) {
    PPROTECTED_PROCESS protectedProc = FindProtectedProcess(ProcessId);
    if (!protectedProc || protectedProc->IsHidden) {
        return STATUS_ALREADY_REGISTERED;
    }

    PEPROCESS process = protectedProc->Process;
    if (!process) return STATUS_INVALID_PARAMETER;

    ULONG_PTR activeProcessLinksOffset = 0x448;

    __try {
        PLIST_ENTRY activeLinks = (PLIST_ENTRY)((PUCHAR)process + activeProcessLinksOffset);

        protectedProc->OriginalFlink = activeLinks->Flink;
        protectedProc->OriginalBlink = activeLinks->Blink;

        PLIST_ENTRY prevEntry = activeLinks->Blink;
        PLIST_ENTRY nextEntry = activeLinks->Flink;

        prevEntry->Flink = nextEntry;
        nextEntry->Blink = prevEntry;

        activeLinks->Flink = activeLinks;
        activeLinks->Blink = activeLinks;

        protectedProc->IsHidden = TRUE;

        DbgLog("Process %p hidden\n", ProcessId);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

// ==================== PROCESS PROTECTION ====================

OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE targetPid = PsGetProcessId(targetProcess);

    PPROTECTED_PROCESS protectedProc = FindProtectedProcess(targetPid);
    if (!protectedProc) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        POB_PRE_CREATE_HANDLE_INFORMATION createInfo =
            &OperationInformation->Parameters->CreateHandleInformation;

        createInfo->DesiredAccess &= ~PROCESS_VM_READ;
        createInfo->DesiredAccess &= ~PROCESS_VM_WRITE;
        createInfo->DesiredAccess &= ~PROCESS_VM_OPERATION;
        createInfo->DesiredAccess &= ~PROCESS_QUERY_INFORMATION;
        createInfo->DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
        createInfo->DesiredAccess &= ~PROCESS_TERMINATE;
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS RegisterProcessProtection() {
    OB_OPERATION_REGISTRATION opReg = { 0 };
    OB_CALLBACK_REGISTRATION callbackReg = { 0 };

    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = PreOperationCallback;
    opReg.PostOperation = NULL;

    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"385200");

    callbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    callbackReg.OperationRegistrationCount = 1;
    callbackReg.Altitude = altitude;
    callbackReg.RegistrationContext = NULL;
    callbackReg.OperationRegistration = &opReg;

    return ObRegisterCallbacks(&callbackReg, &g_Context->CallbackHandle);
}

// ==================== CALLBACKS ====================

VOID ProcessNotifyCallback(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);

    if (!g_Context || !g_Context->MonitoringEnabled) return;

    if (Create) {
        PEPROCESS process;
        NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
        if (!NT_SUCCESS(status)) return;

        PCHAR procName = PsGetProcessImageFileName(process);
        if (procName && wcslen(g_Context->TargetProcessName) > 0) {
            WCHAR wProcName[260];
            ANSI_STRING ansi;
            UNICODE_STRING unicode;

            RtlInitAnsiString(&ansi, procName);
            unicode.Buffer = wProcName;
            unicode.MaximumLength = sizeof(wProcName);
            unicode.Length = 0;

            status = RtlAnsiStringToUnicodeString(&unicode, &ansi, FALSE);

            if (NT_SUCCESS(status) && _wcsicmp(wProcName, g_Context->TargetProcessName) == 0) {
                PPROTECTED_PROCESS protectedProc =
                    (PPROTECTED_PROCESS)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, sizeof(PROTECTED_PROCESS), TAG_POOL);

                if (protectedProc) {
                    RtlZeroMemory(protectedProc, sizeof(PROTECTED_PROCESS));
                    protectedProc->ProcessId = ProcessId;
                    protectedProc->Process = process;
                    protectedProc->IsHidden = FALSE;
                    InitializeListHead(&protectedProc->HookList);

                    KIRQL oldIrql;
                    KeAcquireSpinLock(&g_Context->ProcessListLock, &oldIrql);
                    InsertTailList(&g_Context->ProcessList, &protectedProc->ListEntry);
                    KeReleaseSpinLock(&g_Context->ProcessListLock, oldIrql);

                    DbgLog("Target found: PID=%p Name=%s\n", ProcessId, procName);
                    return;
                }
            }
        }

        ObDereferenceObject(process);
    }
    else {
        PPROTECTED_PROCESS protectedProc = FindProtectedProcess(ProcessId);
        if (protectedProc) {
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_Context->ProcessListLock, &oldIrql);

            while (!IsListEmpty(&protectedProc->HookList)) {
                PLIST_ENTRY entry = RemoveHeadList(&protectedProc->HookList);
                PFUNCTION_HOOK hook = CONTAINING_RECORD(entry, FUNCTION_HOOK, ListEntry);
                ExFreePoolWithTag(hook, TAG_HOOK);
            }

            RemoveEntryList(&protectedProc->ListEntry);
            KeReleaseSpinLock(&g_Context->ProcessListLock, oldIrql);

            if (protectedProc->Process) ObDereferenceObject(protectedProc->Process);
            ExFreePoolWithTag(protectedProc, TAG_POOL);
        }
    }
}

// ==================== DEVICE CONTROL ====================

NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

    switch (ioControlCode) {
    case IOCTL_SET_TARGET: {
        if (inputLength < sizeof(WCHAR) * 2) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PWCHAR targetName = (PWCHAR)inputBuffer;
        RtlStringCbCopyW(g_Context->TargetProcessName,
            sizeof(g_Context->TargetProcessName), targetName);
        DbgLog("Target: %ws\n", targetName);
        break;
    }

    case IOCTL_ENABLE_MONITOR: {
        if (inputLength < sizeof(BOOLEAN)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        g_Context->MonitoringEnabled = *(PBOOLEAN)inputBuffer;
        DbgLog("Monitor: %d\n", g_Context->MonitoringEnabled);
        break;
    }

    case IOCTL_READ_MEMORY: {
        if (inputLength < sizeof(MEMORY_OPERATION) ||
            outputLength < sizeof(MEMORY_OPERATION)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PMEMORY_OPERATION memOp = (PMEMORY_OPERATION)inputBuffer;
        PMEMORY_OPERATION output = (PMEMORY_OPERATION)outputBuffer;

        status = ReadProcessMemory(memOp->ProcessId, memOp->Address,
            output->Buffer, (SIZE_T)memOp->Size);

        if (NT_SUCCESS(status)) {
            bytesReturned = (ULONG)(sizeof(MEMORY_OPERATION) + memOp->Size);
        }
        break;
    }

    case IOCTL_WRITE_MEMORY: {
        if (inputLength < sizeof(MEMORY_OPERATION)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PMEMORY_OPERATION memOp = (PMEMORY_OPERATION)inputBuffer;
        status = WriteProcessMemory(memOp->ProcessId, memOp->Address,
            memOp->Buffer, (SIZE_T)memOp->Size);
        break;
    }

    case IOCTL_GET_MODULE: {
        if (inputLength < sizeof(MODULE_REQUEST) ||
            outputLength < sizeof(MODULE_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PMODULE_REQUEST modReq = (PMODULE_REQUEST)inputBuffer;
        PMODULE_RESPONSE modResp = (PMODULE_RESPONSE)outputBuffer;

        status = GetModuleBase(modReq->ProcessId, modReq->ModuleName,
            &modResp->BaseAddress, &modResp->Size);

        if (NT_SUCCESS(status)) {
            bytesReturned = sizeof(MODULE_RESPONSE);
        }
        break;
    }

    case IOCTL_INSTALL_HOOK: {
        if (inputLength < sizeof(HOOK_REQUEST)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PHOOK_REQUEST hookReq = (PHOOK_REQUEST)inputBuffer;
        status = InstallInlineHook(hookReq->ProcessId, hookReq->TargetAddress,
            hookReq->HookCode, hookReq->HookSize);
        break;
    }

    case IOCTL_REMOVE_HOOK: {
        if (inputLength < sizeof(HOOK_REQUEST)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PHOOK_REQUEST hookReq = (PHOOK_REQUEST)inputBuffer;
        status = RemoveHook(hookReq->ProcessId, hookReq->TargetAddress);
        break;
    }

    case IOCTL_HIDE_PROCESS: {
        if (inputLength < sizeof(HANDLE)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        HANDLE pid = *(PHANDLE)inputBuffer;
        status = HideProcessFromList(pid);
        break;
    }

    case IOCTL_PROTECT_PROCESS: {
        if (inputLength < sizeof(PROCESS_REQUEST)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PPROCESS_REQUEST procReq = (PPROCESS_REQUEST)inputBuffer;
        PPROTECTED_PROCESS existingProc = FindProtectedProcess(procReq->ProcessId);

        if (procReq->Enable && !existingProc) {
            PEPROCESS process;
            status = PsLookupProcessByProcessId(procReq->ProcessId, &process);

            if (NT_SUCCESS(status)) {
                PPROTECTED_PROCESS protectedProc =
                    (PPROTECTED_PROCESS)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, sizeof(PROTECTED_PROCESS), TAG_POOL);

                if (protectedProc) {
                    RtlZeroMemory(protectedProc, sizeof(PROTECTED_PROCESS));
                    protectedProc->ProcessId = procReq->ProcessId;
                    protectedProc->Process = process;
                    protectedProc->IsHidden = FALSE;
                    InitializeListHead(&protectedProc->HookList);

                    KIRQL oldIrql;
                    KeAcquireSpinLock(&g_Context->ProcessListLock, &oldIrql);
                    InsertTailList(&g_Context->ProcessList, &protectedProc->ListEntry);
                    KeReleaseSpinLock(&g_Context->ProcessListLock, oldIrql);

                    DbgLog("Process %p protected\n", procReq->ProcessId);
                    status = STATUS_SUCCESS;
                }
                else {
                    ObDereferenceObject(process);
                    status = STATUS_INSUFFICIENT_RESOURCES;
                }
            }
        }
        else if (!procReq->Enable && existingProc) {
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_Context->ProcessListLock, &oldIrql);
            RemoveEntryList(&existingProc->ListEntry);
            KeReleaseSpinLock(&g_Context->ProcessListLock, oldIrql);

            if (existingProc->Process) ObDereferenceObject(existingProc->Process);
            ExFreePoolWithTag(existingProc, TAG_POOL);

            DbgLog("Process %p unprotected\n", procReq->ProcessId);
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_ALREADY_REGISTERED;
        }
        break;
    }

    default:
        DbgLog("Unknown IOCTL: 0x%08X\n", ioControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ==================== DRIVER LIFECYCLE ====================

NTSTATUS DeviceCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (!g_Context) return;

    DbgLog("Driver unloading...\n");

    if (g_Context->CallbackHandle) {
        ObUnRegisterCallbacks(g_Context->CallbackHandle);
    }

    PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Context->ProcessListLock, &oldIrql);

    while (!IsListEmpty(&g_Context->ProcessList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_Context->ProcessList);
        PPROTECTED_PROCESS proc = CONTAINING_RECORD(entry, PROTECTED_PROCESS, ListEntry);

        while (!IsListEmpty(&proc->HookList)) {
            PLIST_ENTRY hookEntry = RemoveHeadList(&proc->HookList);
            PFUNCTION_HOOK hook = CONTAINING_RECORD(hookEntry, FUNCTION_HOOK, ListEntry);

            WriteProcessMemory(proc->ProcessId, hook->TargetAddress,
                hook->OriginalBytes, hook->HookSize);

            ExFreePoolWithTag(hook, TAG_HOOK);
        }

        if (proc->Process) ObDereferenceObject(proc->Process);
        ExFreePoolWithTag(proc, TAG_POOL);
    }

    KeReleaseSpinLock(&g_Context->ProcessListLock, oldIrql);

    if (g_Context->DeviceObject) {
        UNICODE_STRING dosName;
        RtlInitUnicodeString(&dosName, DOS_NAME);
        IoDeleteSymbolicLink(&dosName);
        IoDeleteDevice(g_Context->DeviceObject);
    }

    ExFreePoolWithTag(g_Context, TAG_POOL);
    g_Context = NULL;

    DbgLog("Driver unloaded successfully\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    UNICODE_STRING deviceName, dosDeviceName;

    DbgLog("Driver loading...\n");

    g_Context = (PDRIVER_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(DRIVER_CONTEXT), TAG_POOL);

    if (!g_Context) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_Context, sizeof(DRIVER_CONTEXT));
    InitializeListHead(&g_Context->ProcessList);
    KeInitializeSpinLock(&g_Context->ProcessListLock);

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_Context->DeviceObject);

    if (!NT_SUCCESS(status)) {
        DbgLog("IoCreateDevice failed: 0x%08X\n", status);
        ExFreePoolWithTag(g_Context, TAG_POOL);
        return status;
    }

    g_Context->DeviceObject->Flags |= DO_DIRECT_IO;
    g_Context->DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlInitUnicodeString(&dosDeviceName, DOS_NAME);

    status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgLog("IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_Context->DeviceObject);
        ExFreePoolWithTag(g_Context, TAG_POOL);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgLog("PsSetCreateProcessNotifyRoutine failed: 0x%08X\n", status);
        IoDeleteSymbolicLink(&dosDeviceName);
        IoDeleteDevice(g_Context->DeviceObject);
        ExFreePoolWithTag(g_Context, TAG_POOL);
        return status;
    }

    status = RegisterProcessProtection();
    if (!NT_SUCCESS(status)) {
        DbgLog("RegisterProcessProtection failed: 0x%08X (non-critical)\n", status);
        // Não é crítico, continuar
    }


    DbgLog("========================================\n");
    DbgLog("[+] Driver loaded successfully!\n");
    DbgLog("========================================\n");
    return STATUS_SUCCESS;
}