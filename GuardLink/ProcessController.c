#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include "shared_defs.h"

// Declarações forward necessárias de ntifs.h sem incluir o header completo
typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];
    PKPROCESS Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;
} KAPC_STATE, * PKAPC_STATE, * PRKAPC_STATE;

// Protótipos de funções do kernel
NTKERNELAPI VOID KeStackAttachProcess(
    _In_ PKPROCESS Process,
    _Out_ PRKAPC_STATE ApcState
);

NTKERNELAPI VOID KeUnstackDetachProcess(
    _In_ PRKAPC_STATE ApcState
);

// ==================== CONFIGURAÇÃO ====================

#define DEVICE_NAME_SEED 0x4D2F8A3C
#define DOS_NAME_SEED 0x7B9E1D5A

// Tags
#define TAG_POOL 'looP'
#define TAG_FILE 'eliF'
#define TAG_NTFS 'stfN'

// Process Access Rights
#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE 0x0020
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_QUERY_INFORMATION 0x0400
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define PROCESS_SUSPEND_RESUME 0x0800
#define PROCESS_TERMINATE 0x0001
 
#define _DEBUG

#ifdef _DEBUG
#define DbgLog(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Drv] " fmt, __VA_ARGS__)
#else
#define DbgLog(fmt, ...) ((void)0)
#endif

// ==================== ESTRUTURAS ====================

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

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} MY_PEB_LDR_DATA, * PMY_PEB_LDR_DATA;

typedef struct _MY_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PMY_PEB_LDR_DATA Ldr;
} MY_PEB, * PMY_PEB;

typedef struct _PROTECTED_PROCESS {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    PEPROCESS Process;
    LIST_ENTRY HookList;
    LIST_ENTRY ModuleList;
    ULONG Flags;
    UCHAR ProcessNameHash[32];
    PVOID ObHandle;
    BOOLEAN IsHidden;
    PLIST_ENTRY OriginalFlink;
    PLIST_ENTRY OriginalBlink;
} PROTECTED_PROCESS, * PPROTECTED_PROCESS;

typedef struct _FUNCTION_HOOK {
    LIST_ENTRY ListEntry;
    PVOID TargetAddress;
    UCHAR OriginalBytes[16];
    ULONG HookSize;
    ULONG Flags;
} FUNCTION_HOOK, * PFUNCTION_HOOK;

typedef struct _MODULE_ENTRY {
    LIST_ENTRY ListEntry;
    PVOID BaseAddress;
    ULONG Size;
    ULONG NameHash;
} MODULE_ENTRY, * PMODULE_ENTRY;

// ==================== IMPORTS ====================

extern NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(IN HANDLE ProcessId, OUT PEPROCESS* Process);
extern NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);
extern NTKERNELAPI PCHAR PsGetProcessImageFileName(IN PEPROCESS Process);
extern NTKERNELAPI HANDLE PsGetProcessId(IN PEPROCESS Process);
extern POBJECT_TYPE* PsProcessType;

// ==================== CONTEXTO GLOBAL ====================

typedef struct _DRIVER_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    LIST_ENTRY ProcessList;
    KSPIN_LOCK ProcessListLock;
    ULONG TargetProcessHash;
    BOOLEAN MonitoringEnabled;
    DYNAMIC_IOCTL_MAP IoctlMap;
    KSPIN_LOCK IoctlMapLock;
    LARGE_INTEGER LastUpdate;
    PVOID CallbackHandle;
} DRIVER_CONTEXT, * PDRIVER_CONTEXT;

PDRIVER_CONTEXT g_Context = NULL;

// ==================== CRIPTOGRAFIA ====================

VOID GenerateEncryptionKey(PUCHAR key, ULONG size) {
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);

    ULONG seed = (ULONG)(time.QuadPart & 0xFFFFFFFF);
    for (ULONG i = 0; i < size; i++) {
        seed = (seed * 1103515245 + 12345);
        key[i] = (UCHAR)(seed >> 16);
    }
}

VOID XorEncryptDecrypt(PUCHAR data, ULONG dataSize, PUCHAR key, ULONG keySize) {
    if (!data || !key || keySize == 0) return;

    for (ULONG i = 0; i < dataSize; i++) {
        data[i] ^= key[i % keySize];
    }
}

ULONG CalculateChecksum(PUCHAR data, ULONG size) {
    ULONG hash = 0x811C9DC5;
    for (ULONG i = 0; i < size; i++) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}

// ==================== UTILIDADES ====================

ULONG CalculateHash(const WCHAR* str) {
    if (!str) return 0;

    ULONG hash = 0x811C9DC5;
    while (*str) {
        WCHAR lower = (*str >= L'A' && *str <= L'Z') ? (*str + 32) : *str;
        hash ^= (UCHAR)lower;
        hash *= 0x01000193;
        str++;
    }
    return hash;
}

VOID GenerateRandomDeviceName(PWCHAR buffer, ULONG bufferSize, ULONG seed) {
    WCHAR chars[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    ULONG charCount = (ULONG)wcslen(chars);

    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    seed ^= (ULONG)(time.QuadPart & 0xFFFFFFFF);

    RtlStringCbCopyW(buffer, bufferSize, L"\\Device\\");
    ULONG offset = (ULONG)wcslen(buffer);

    for (ULONG i = 0; i < 12; i++) {
        seed = (seed * 1103515245 + 12345);
        buffer[offset + i] = chars[(seed >> 16) % charCount];
    }
    buffer[offset + 12] = L'\0';
}

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

// ==================== DYNAMIC IOCTL ====================

NTSTATUS InitializeObfuscatedIoctl() {
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);

    KeInitializeSpinLock(&g_Context->IoctlMapLock);

    g_Context->IoctlMap.Timestamp = (ULONG)(time.QuadPart / 10000000);  // Timestamp em segundos
    g_Context->IoctlMap.RandomSeed = (ULONG)((time.QuadPart >> 32) & 0xFFFFFFFF);

    DbgLog("=== Initializing IOCTL Map ===\n");
    DbgLog("Timestamp: %lu\n", g_Context->IoctlMap.Timestamp);
    DbgLog("Random Seed: 0x%08X\n", g_Context->IoctlMap.RandomSeed);

    ULONG seed = g_Context->IoctlMap.RandomSeed;
    for (int i = 0; i < MAX_COMMANDS; i++) {
        seed = (seed * 1103515245 + 12345);
        g_Context->IoctlMap.CommandTable[i] = seed;
        DbgLog("Command[%d] = 0x%08X\n", i, g_Context->IoctlMap.CommandTable[i]);
    }

    GenerateEncryptionKey(g_Context->IoctlMap.XorKey, ENCRYPTION_KEY_SIZE);
    g_Context->LastUpdate = time;

    DbgLog("IOCTL Map initialized successfully\n");
    DbgLog("================================\n");

    return STATUS_SUCCESS;
}

BOOLEAN ValidateCommandHash(ULONG commandHash, PULONG commandIndex) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Context->IoctlMapLock, &oldIrql);

    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    LONGLONG timeDiff = (currentTime.QuadPart - g_Context->LastUpdate.QuadPart) / 10000000;

    if (timeDiff > 300) {
        ULONG seed = g_Context->IoctlMap.RandomSeed ^ (ULONG)currentTime.QuadPart;
        for (int i = 0; i < MAX_COMMANDS; i++) {
            seed = (seed * 1103515245 + 12345);
            g_Context->IoctlMap.CommandTable[i] = seed;
        }
        g_Context->LastUpdate = currentTime;
        DbgLog("Command table rotated\n");
    }

    BOOLEAN found = FALSE;
    for (int i = 0; i < MAX_COMMANDS; i++) {
        if (g_Context->IoctlMap.CommandTable[i] == commandHash) {
            *commandIndex = i;
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_Context->IoctlMapLock, oldIrql);
    return found;
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

    KeStackAttachProcess(process, &apcState);

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
    _In_ ULONG ModuleNameHash,
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

    KeStackAttachProcess(process, &apcState);

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
                ULONG hash = CalculateHash(ldrEntry->BaseDllName.Buffer);

                if (hash == ModuleNameHash) {
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

    // Usando ExAllocatePool2 (Windows 10 2004+)
    PFUNCTION_HOOK hook = (PFUNCTION_HOOK)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(FUNCTION_HOOK), TAG_POOL);

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

    DbgLog("Hook installed at %p (size=%lu)\n", TargetAddress, HookSize);

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

    ExFreePoolWithTag(hookToRemove, TAG_POOL);

    DbgLog("Hook removed from %p\n", TargetAddress);

    return status;
}

// ==================== DKOM - PROCESS HIDING ====================

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

        DbgLog("Process %p hidden from list\n", ProcessId);

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

NTSTATUS UnhideProcess(_In_ HANDLE ProcessId) {
    PPROTECTED_PROCESS protectedProc = FindProtectedProcess(ProcessId);
    if (!protectedProc || !protectedProc->IsHidden) {
        return STATUS_NOT_FOUND;
    }

    PEPROCESS process = protectedProc->Process;
    ULONG_PTR activeProcessLinksOffset = 0x448;

    __try {
        PLIST_ENTRY activeLinks = (PLIST_ENTRY)((PUCHAR)process + activeProcessLinksOffset);

        activeLinks->Flink = protectedProc->OriginalFlink;
        activeLinks->Blink = protectedProc->OriginalBlink;

        protectedProc->OriginalFlink->Blink = activeLinks;
        protectedProc->OriginalBlink->Flink = activeLinks;

        protectedProc->IsHidden = FALSE;

        DbgLog("Process %p unhidden\n", ProcessId);

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

// ==================== ObRegisterCallbacks - PROCESS PROTECTION ====================

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
        createInfo->DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
        createInfo->DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
        createInfo->DesiredAccess &= ~PROCESS_TERMINATE;

        DbgLog("Protected process %p from handle creation\n", targetPid);
    }
    else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        POB_PRE_DUPLICATE_HANDLE_INFORMATION dupInfo =
            &OperationInformation->Parameters->DuplicateHandleInformation;

        dupInfo->DesiredAccess &= ~PROCESS_VM_READ;
        dupInfo->DesiredAccess &= ~PROCESS_VM_WRITE;
        dupInfo->DesiredAccess &= ~PROCESS_VM_OPERATION;
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

    NTSTATUS status = ObRegisterCallbacks(&callbackReg, &g_Context->CallbackHandle);

    if (NT_SUCCESS(status)) {
        DbgLog("Process protection callbacks registered\n");
    }
    else {
        DbgLog("Failed to register callbacks: %08X\n", status);
    }

    return status;
}

VOID UnregisterProcessProtection() {
    if (g_Context->CallbackHandle) {
        ObUnRegisterCallbacks(g_Context->CallbackHandle);
        g_Context->CallbackHandle = NULL;
        DbgLog("Process protection callbacks unregistered\n");
    }
}

// ==================== CALLBACKS ====================

NTSTATUS AnsiToUnicode(PCHAR AnsiString, PWCHAR UnicodeBuffer, ULONG BufferSize) {
    ANSI_STRING ansi;
    UNICODE_STRING unicode;

    RtlInitAnsiString(&ansi, AnsiString);
    unicode.Buffer = UnicodeBuffer;
    unicode.MaximumLength = (USHORT)BufferSize;
    unicode.Length = 0;

    return RtlAnsiStringToUnicodeString(&unicode, &ansi, FALSE);
}

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
        if (procName) {
            WCHAR wProcName[260];

            status = AnsiToUnicode(procName, wProcName, sizeof(wProcName));

            if (NT_SUCCESS(status)) {
                ULONG hash = CalculateHash(wProcName);

                if (hash == g_Context->TargetProcessHash) {
                    PPROTECTED_PROCESS protectedProc =
                        (PPROTECTED_PROCESS)ExAllocatePool2(
                            POOL_FLAG_NON_PAGED, sizeof(PROTECTED_PROCESS), TAG_POOL);

                    if (protectedProc) {
                        RtlZeroMemory(protectedProc, sizeof(PROTECTED_PROCESS));
                        protectedProc->ProcessId = ProcessId;
                        protectedProc->Process = process;
                        protectedProc->Flags = 0x01;
                        protectedProc->IsHidden = FALSE;
                        protectedProc->ObHandle = NULL;

                        RtlCopyMemory(protectedProc->ProcessNameHash, &hash, sizeof(ULONG));

                        InitializeListHead(&protectedProc->HookList);
                        InitializeListHead(&protectedProc->ModuleList);

                        KIRQL oldIrql;
                        KeAcquireSpinLock(&g_Context->ProcessListLock, &oldIrql);
                        InsertTailList(&g_Context->ProcessList, &protectedProc->ListEntry);
                        KeReleaseSpinLock(&g_Context->ProcessListLock, oldIrql);

                        DbgLog("Target process detected: PID=%p, Name=%s\n", ProcessId, procName);

                        return;
                    }
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
                ExFreePoolWithTag(hook, TAG_POOL);
            }

            while (!IsListEmpty(&protectedProc->ModuleList)) {
                PLIST_ENTRY entry = RemoveHeadList(&protectedProc->ModuleList);
                PMODULE_ENTRY module = CONTAINING_RECORD(entry, MODULE_ENTRY, ListEntry);
                ExFreePoolWithTag(module, TAG_FILE);
            }

            RemoveEntryList(&protectedProc->ListEntry);
            KeReleaseSpinLock(&g_Context->ProcessListLock, oldIrql);

            if (protectedProc->Process) ObDereferenceObject(protectedProc->Process);
            ExFreePoolWithTag(protectedProc, TAG_POOL);

            DbgLog("Process %p removed from protection\n", ProcessId);
        }
    }
}

VOID ThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ThreadId);
    UNREFERENCED_PARAMETER(Create);
}

VOID ImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (g_Context->MonitoringEnabled && FullImageName && FullImageName->Buffer) {
        WCHAR* fileName = wcsrchr(FullImageName->Buffer, L'\\');
        if (fileName) {
            fileName++;

            const WCHAR* antiCheatDlls[] = {
                L"BEService.dll",
                L"BEDaisy.sys",
                L"EasyAntiCheat.dll",
                L"vgk.sys",
                L"vgc.exe"
            };

            for (int i = 0; i < sizeof(antiCheatDlls) / sizeof(WCHAR*); i++) {
                if (_wcsicmp(fileName, antiCheatDlls[i]) == 0) {
                    DbgLog("Anti-cheat detected: %ws in PID=%p\n", fileName, ProcessId);
                    break;
                }
            }
        }
    }
}

// ==================== HANDSHAKE ====================

NTSTATUS HandleHandshake(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesReturned)
{
    DbgLog("=== HandleHandshake START ===\n");
    DbgLog("InputLength: %lu, OutputLength: %lu\n", InputLength, OutputLength);

    // Validação de tamanhos
    if (InputLength < sizeof(HANDSHAKE_REQUEST)) {
        DbgLog("[-] Input buffer too small: %lu < %llu\n", InputLength, sizeof(HANDSHAKE_REQUEST));
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (OutputLength < sizeof(HANDSHAKE_RESPONSE)) {
        DbgLog("[-] Output buffer too small: %lu < %llu\n", OutputLength, sizeof(HANDSHAKE_RESPONSE));
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Validação de ponteiros
    if (!InputBuffer || !OutputBuffer || !BytesReturned) {
        DbgLog("[-] NULL pointer detected\n");
        *BytesReturned = 0;
        return STATUS_INVALID_PARAMETER;
    }

    PHANDSHAKE_REQUEST request = (PHANDSHAKE_REQUEST)InputBuffer;
    PHANDSHAKE_RESPONSE response = (PHANDSHAKE_RESPONSE)OutputBuffer;

    DbgLog("[+] Request Version: %lu\n", request->ClientVersion);
    DbgLog("[+] Request Timestamp: %lu\n", request->ClientTimestamp);

    // Validar versão
    if (request->ClientVersion != 1) {
        DbgLog("[-] Version mismatch: %lu != 1\n", request->ClientVersion);
        *BytesReturned = 0;
        return STATUS_REVISION_MISMATCH;
    }

    // Obter timestamp atual
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    ULONG currentTimestamp = (ULONG)(currentTime.QuadPart / 10000000);

    DbgLog("[+] Server Timestamp: %lu\n", currentTimestamp);

    LONG timeDiff = (LONG)(currentTimestamp - request->ClientTimestamp);
    if (timeDiff < 0) timeDiff = -timeDiff;

    DbgLog("[+] Time difference: %ld seconds\n", timeDiff);

    if (timeDiff > 300) {
        DbgLog("[-] Timestamp too old: %ld > 300\n", timeDiff);
        *BytesReturned = 0;
        return STATUS_TIMEOUT;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Context->IoctlMapLock, &oldIrql);

    RtlZeroMemory(response, sizeof(HANDSHAKE_RESPONSE));

    response->ServerVersion = 1;
    response->ServerTimestamp = g_Context->IoctlMap.Timestamp;
    
    DbgLog("[+] Copying IOCTL map (size: %llu)\n", sizeof(DYNAMIC_IOCTL_MAP));
    RtlCopyMemory(&response->IoctlMap, &g_Context->IoctlMap, sizeof(DYNAMIC_IOCTL_MAP));

    // Gerar nonce do servidor
    ULONG seed = g_Context->IoctlMap.RandomSeed ^ currentTimestamp;
    for (int i = 0; i < 32; i++) {
        seed = (seed * 1103515245 + 12345);
        response->ServerNonce[i] = (UCHAR)(seed >> 16);
    }

    KeReleaseSpinLock(&g_Context->IoctlMapLock, oldIrql);

    *BytesReturned = sizeof(HANDSHAKE_RESPONSE);

    DbgLog("[+] Handshake successful! Returning %lu bytes\n", *BytesReturned);
    DbgLog("[+] Response Version: %lu\n", response->ServerVersion);
    DbgLog("[+] Response Timestamp: %lu\n", response->ServerTimestamp);
    DbgLog("=== HandleHandshake END ===\n");

    return STATUS_SUCCESS;
}

// ==================== DEVICE CONTROL ====================

NTSTATUS HandleCommand(
    _In_ POBFUSCATED_REQUEST request,
    _In_ ULONG inputLength,
    _Out_ PVOID outputBuffer,
    _In_ ULONG outputLength,
    _Out_ PULONG bytesReturned)
{
    NTSTATUS status = STATUS_SUCCESS;
    *bytesReturned = 0;

    DbgLog("=== HandleCommand START ===\n");
    DbgLog("Input Length: %lu\n", inputLength);
    DbgLog("Output Length: %lu\n", outputLength);

    if (inputLength < sizeof(OBFUSCATED_REQUEST)) {
        DbgLog("[-] Input buffer too small\n");
        return STATUS_INVALID_PARAMETER;
    }

    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    ULONG currentMinute = (ULONG)((time.QuadPart / 10000000) / 60);
    ULONG expectedMagic = currentMinute ^ 0xDEADBEEF;

    DbgLog("Magic received: 0x%08X\n", request->Magic);
    DbgLog("Magic expected: 0x%08X\n", expectedMagic);

    ULONG prevMinuteMagic = (currentMinute - 1) ^ 0xDEADBEEF;
    if (request->Magic != expectedMagic && request->Magic != prevMinuteMagic) {
        DbgLog("[-] Invalid magic: %08X (expected %08X or %08X)\n",
            request->Magic, expectedMagic, prevMinuteMagic);
        return STATUS_ACCESS_DENIED;
    }

    // Validar command hash
    ULONG commandIndex;
    if (!ValidateCommandHash(request->CommandHash, &commandIndex)) {
        DbgLog("[-] Invalid command hash: %08X\n", request->CommandHash);
        return STATUS_INVALID_PARAMETER;
    }

    DbgLog("[+] Command index: %lu\n", commandIndex);

    if (request->PayloadSize > 4096) {
        DbgLog("[-] Payload too large: %lu\n", request->PayloadSize);
        return STATUS_INVALID_PARAMETER;
    }

    DbgLog("[+] Payload size: %lu\n", request->PayloadSize);

    // Descriptografar payload
    UCHAR decryptedPayload[4096];
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_Context->IoctlMapLock, &oldIrql);

    // Copiar antes de descriptografar
    RtlCopyMemory(decryptedPayload, request->EncryptedPayload, request->PayloadSize);

    // Descriptografar
    XorEncryptDecrypt(decryptedPayload, request->PayloadSize,
        g_Context->IoctlMap.XorKey, ENCRYPTION_KEY_SIZE);

    KeReleaseSpinLock(&g_Context->IoctlMapLock, oldIrql);

    // Validar checksum
    ULONG calculatedChecksum = CalculateChecksum(decryptedPayload, request->PayloadSize);

    DbgLog("Checksum received: 0x%08X\n", request->Checksum);
    DbgLog("Checksum calculated: 0x%08X\n", calculatedChecksum);

    if (calculatedChecksum != request->Checksum) {
        DbgLog("[-] Checksum mismatch!\n");
        return STATUS_DATA_ERROR;
    }

    DbgLog("[+] Checksum validated\n");

    // Processar comando
    switch (commandIndex) {
    case CMD_SET_TARGET: {
        DbgLog("[CMD] SET_TARGET\n");

        if (request->PayloadSize < sizeof(WCHAR) * 2) {
            DbgLog("[-] Payload too small for SET_TARGET\n");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PWCHAR targetName = (PWCHAR)decryptedPayload;

        // Validar string unicode
        BOOLEAN validString = FALSE;
        for (ULONG i = 0; i < request->PayloadSize / sizeof(WCHAR); i++) {
            if (targetName[i] == L'\0') {
                validString = TRUE;
                break;
            }
        }

        if (!validString) {
            DbgLog("[-] Invalid unicode string\n");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        g_Context->TargetProcessHash = CalculateHash(targetName);

        DbgLog("[+] Target set: %ws (hash=0x%08X)\n", targetName, g_Context->TargetProcessHash);
        status = STATUS_SUCCESS;
        break;
    }

    case CMD_ENABLE_MONITOR: {
        DbgLog("[CMD] ENABLE_MONITOR\n");

        if (request->PayloadSize < sizeof(BOOLEAN)) {
            DbgLog("[-] Payload too small for ENABLE_MONITOR\n");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        BOOLEAN enable = *(PBOOLEAN)decryptedPayload;
        g_Context->MonitoringEnabled = enable;

        DbgLog("[+] Monitoring: %s\n", enable ? "ENABLED" : "DISABLED");
        status = STATUS_SUCCESS;
        break;
    }

    case CMD_READ_MEMORY: {
        DbgLog("[CMD] READ_MEMORY\n");

        if (request->PayloadSize < sizeof(MEMORY_OPERATION)) {
            DbgLog("[-] Payload too small for READ_MEMORY\n");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (outputLength < sizeof(MEMORY_OPERATION)) {
            DbgLog("[-] Output buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PMEMORY_OPERATION memOp = (PMEMORY_OPERATION)decryptedPayload;
        PMEMORY_OPERATION output = (PMEMORY_OPERATION)outputBuffer;

        DbgLog("[+] Reading: PID=%p, Addr=%p, Size=%llu\n",
            memOp->ProcessId, memOp->Address, memOp->Size);

        status = ReadProcessMemory(memOp->ProcessId, memOp->Address,
            output->Buffer, memOp->Size);

        if (NT_SUCCESS(status)) {
            *bytesReturned = (ULONG)(sizeof(MEMORY_OPERATION) + memOp->Size);
            DbgLog("[+] Read successful, returning %lu bytes\n", *bytesReturned);
        }
        else {
            DbgLog("[-] Read failed: 0x%08X\n", status);
        }
        break;
    }

    case CMD_WRITE_MEMORY: {
        DbgLog("[CMD] WRITE_MEMORY\n");

        if (request->PayloadSize < sizeof(MEMORY_OPERATION)) {
            DbgLog("[-] Payload too small for WRITE_MEMORY\n");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PMEMORY_OPERATION memOp = (PMEMORY_OPERATION)decryptedPayload;

        DbgLog("[+] Writing: PID=%p, Addr=%p, Size=%llu\n",
            memOp->ProcessId, memOp->Address, memOp->Size);

        status = WriteProcessMemory(memOp->ProcessId, memOp->Address,
            memOp->Buffer, memOp->Size);

        if (NT_SUCCESS(status)) {
            DbgLog("[+] Write successful\n");
        }
        else {
            DbgLog("[-] Write failed: 0x%08X\n", status);
        }
        break;
    }

    case CMD_GET_MODULE: {
        DbgLog("[CMD] GET_MODULE\n");

        if (request->PayloadSize < sizeof(MODULE_REQUEST)) {
            DbgLog("[-] Payload too small for GET_MODULE\n");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (outputLength < sizeof(MODULE_RESPONSE)) {
            DbgLog("[-] Output buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PMODULE_REQUEST modReq = (PMODULE_REQUEST)decryptedPayload;
        PMODULE_RESPONSE modResp = (PMODULE_RESPONSE)outputBuffer;

        DbgLog("[+] Getting module: %ws\n", modReq->ModuleName);

        ULONG hash = CalculateHash(modReq->ModuleName);
        status = GetModuleBase(modReq->ProcessId, hash,
            &modResp->BaseAddress, &modResp->Size);

        if (NT_SUCCESS(status)) {
            *bytesReturned = sizeof(MODULE_RESPONSE);
            DbgLog("[+] Module found: Base=%p, Size=0x%X\n",
                modResp->BaseAddress, modResp->Size);
        }
        else {
            DbgLog("[-] Module not found: 0x%08X\n", status);
        }
        break;
    }

    case CMD_INSTALL_HOOK: {
        DbgLog("[CMD] INSTALL_HOOK\n");

        if (request->PayloadSize < sizeof(HOOK_REQUEST)) {
            DbgLog("[-] Payload too small for INSTALL_HOOK\n");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PHOOK_REQUEST hookReq = (PHOOK_REQUEST)decryptedPayload;

        DbgLog("[+] Installing hook: Addr=%p, Size=%lu\n",
            hookReq->TargetAddress, hookReq->HookSize);

        status = InstallInlineHook(hookReq->ProcessId, hookReq->TargetAddress,
            hookReq->HookCode, hookReq->HookSize);

        if (NT_SUCCESS(status)) {
            DbgLog("[+] Hook installed\n");
        }
        else {
            DbgLog("[-] Hook failed: 0x%08X\n", status);
        }
        break;
    }

    case CMD_REMOVE_HOOK: {
        DbgLog("[CMD] REMOVE_HOOK\n");

        if (request->PayloadSize < sizeof(HANDLE) + sizeof(PVOID)) {
            DbgLog("[-] Payload too small for REMOVE_HOOK\n");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        HANDLE pid = *(PHANDLE)decryptedPayload;
        PVOID addr = *(PVOID*)(decryptedPayload + sizeof(HANDLE));

        DbgLog("[+] Removing hook: Addr=%p\n", addr);

        status = RemoveHook(pid, addr);

        if (NT_SUCCESS(status)) {
            DbgLog("[+] Hook removed\n");
        }
        else {
            DbgLog("[-] Remove failed: 0x%08X\n", status);
        }
        break;
    }

    case CMD_HIDE_PROCESS: {
        DbgLog("[CMD] HIDE_PROCESS\n");

        if (request->PayloadSize < sizeof(HANDLE)) {
            DbgLog("[-] Payload too small for HIDE_PROCESS\n");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        HANDLE pid = *(PHANDLE)decryptedPayload;

        DbgLog("[+] Hiding process: PID=%p\n", pid);

        status = HideProcessFromList(pid);

        if (NT_SUCCESS(status)) {
            DbgLog("[+] Process hidden\n");
        }
        else {
            DbgLog("[-] Hide failed: 0x%08X\n", status);
        }
        break;
    }

    case CMD_PROTECT_PROCESS: {
        DbgLog("[CMD] PROTECT_PROCESS\n");

        if (request->PayloadSize < sizeof(PROCESS_REQUEST)) {
            DbgLog("[-] Payload too small for PROTECT_PROCESS\n");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PPROCESS_REQUEST procReq = (PPROCESS_REQUEST)decryptedPayload;

        DbgLog("[+] Protecting: %ws (PID=%p)\n",
            procReq->ProcessName, procReq->ProcessId);

        status = STATUS_SUCCESS;
        break;
    }

    default:
        DbgLog("[-] Unknown command index: %lu\n", commandIndex);
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }

    DbgLog("=== HandleCommand END (Status=0x%08X) ===\n\n", status);
    return status;
}

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

    DbgLog("\n=== DeviceControl Called ===\n");
    DbgLog("IOCTL Code: 0x%08X\n", ioControlCode);
    DbgLog("Input Length: %lu\n", inputLength);
    DbgLog("Output Length: %lu\n", outputLength);
    DbgLog("Input Buffer: %p\n", inputBuffer);
    DbgLog("Output Buffer: %p\n", outputBuffer);

    ULONG handshakeIoctl = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
    ULONG commandIoctl = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);

    DbgLog("Expected Handshake IOCTL: 0x%08X\n", handshakeIoctl);
    DbgLog("Expected Command IOCTL: 0x%08X\n", commandIoctl);

    if (ioControlCode == handshakeIoctl) {
        DbgLog("[+] Handshake IOCTL detected\n");
        status = HandleHandshake(inputBuffer, inputLength, outputBuffer,
            outputLength, &bytesReturned);

        DbgLog("HandleHandshake returned: 0x%08X\n", status);
        DbgLog("Bytes to return: %lu\n", bytesReturned);
    }
    else if (ioControlCode == commandIoctl) {
        DbgLog("[+] Command IOCTL detected\n");
        status = HandleCommand((POBFUSCATED_REQUEST)inputBuffer, inputLength,
            outputBuffer, outputLength, &bytesReturned);

        DbgLog("HandleCommand returned: 0x%08X\n", status);
        DbgLog("Bytes to return: %lu\n", bytesReturned);
    }
    else {
        DbgLog("[-] Unknown IOCTL: 0x%08X\n", ioControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        bytesReturned = 0;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;

    DbgLog("Final Status: 0x%08X\n", status);
    DbgLog("Final Information: %lu\n", bytesReturned);
    DbgLog("=== DeviceControl End ===\n\n");

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

    UnregisterProcessProtection();
    PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
    PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Context->ProcessListLock, &oldIrql);

    while (!IsListEmpty(&g_Context->ProcessList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_Context->ProcessList);
        PPROTECTED_PROCESS proc = CONTAINING_RECORD(entry, PROTECTED_PROCESS, ListEntry);

        if (proc->IsHidden) {
            UnhideProcess(proc->ProcessId);
        }

        while (!IsListEmpty(&proc->HookList)) {
            PLIST_ENTRY hookEntry = RemoveHeadList(&proc->HookList);
            PFUNCTION_HOOK hook = CONTAINING_RECORD(hookEntry, FUNCTION_HOOK, ListEntry);

            if (hook->Flags & 0x01) {
                WriteProcessMemory(proc->ProcessId, hook->TargetAddress,
                    hook->OriginalBytes, hook->HookSize);
            }

            ExFreePoolWithTag(hook, TAG_POOL);
        }

        while (!IsListEmpty(&proc->ModuleList)) {
            PLIST_ENTRY modEntry = RemoveHeadList(&proc->ModuleList);
            PMODULE_ENTRY module = CONTAINING_RECORD(modEntry, MODULE_ENTRY, ListEntry);
            ExFreePoolWithTag(module, TAG_FILE);
        }

        if (proc->Process) ObDereferenceObject(proc->Process);
        ExFreePoolWithTag(proc, TAG_POOL);
    }

    KeReleaseSpinLock(&g_Context->ProcessListLock, oldIrql);

    if (g_Context->DeviceObject) {
        UNICODE_STRING dosName;
        WCHAR dosNameBuffer[256];
        GenerateRandomDeviceName(dosNameBuffer, sizeof(dosNameBuffer), DOS_NAME_SEED);

        WCHAR dosDeviceName[256];
        RtlStringCbCopyW(dosDeviceName, sizeof(dosDeviceName), L"\\DosDevices\\");
        RtlStringCbCatW(dosDeviceName, sizeof(dosDeviceName), dosNameBuffer + 9);
        RtlInitUnicodeString(&dosName, dosDeviceName);

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
    WCHAR deviceNameBuffer[256];
    WCHAR dosNameBuffer[256];

    DbgLog("Driver loading...\n");

    g_Context = (PDRIVER_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(DRIVER_CONTEXT), TAG_POOL);

    if (!g_Context) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_Context, sizeof(DRIVER_CONTEXT));
    InitializeListHead(&g_Context->ProcessList);
    KeInitializeSpinLock(&g_Context->ProcessListLock);

    status = InitializeObfuscatedIoctl();
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_Context, TAG_POOL);
        return status;
    }

    GenerateRandomDeviceName(deviceNameBuffer, sizeof(deviceNameBuffer), DEVICE_NAME_SEED);
    RtlInitUnicodeString(&deviceName, deviceNameBuffer);

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &g_Context->DeviceObject);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_Context, TAG_POOL);
        return status;
    }

    RtlStringCbCopyW(dosNameBuffer, sizeof(dosNameBuffer), L"\\DosDevices\\");
    RtlStringCbCatW(dosNameBuffer, sizeof(dosNameBuffer), deviceNameBuffer + 9);
    RtlInitUnicodeString(&dosDeviceName, dosNameBuffer);

    status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_Context->DeviceObject);
        ExFreePoolWithTag(g_Context, TAG_POOL);
        return status;
    }

    UNICODE_STRING regPath;
    RtlInitUnicodeString(&regPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\GuardLink\\Parameters");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey;
    NTSTATUS regStatus = ZwCreateKey(&hKey, KEY_WRITE, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (NT_SUCCESS(regStatus)) {
        UNICODE_STRING valueName;
        RtlInitUnicodeString(&valueName, L"DeviceName");

        WCHAR shortName[256];
        RtlStringCbCopyW(shortName, sizeof(shortName), dosNameBuffer + 12);

        ZwSetValueKey(hKey, &valueName, 0, REG_SZ, shortName, (ULONG)(wcslen(shortName) + 1) * sizeof(WCHAR));
        ZwClose(hKey);

        DbgLog("Device name saved to registry: %ws\n", shortName);
    }
    else {
        DbgLog("Warning: Failed to save device name to registry: %08X\n", regStatus);
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) goto Cleanup;

    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);
        goto Cleanup;
    }

    status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    if (!NT_SUCCESS(status)) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);
        goto Cleanup;
    }

    status = RegisterProcessProtection();
    if (!NT_SUCCESS(status)) {
        DbgLog("Warning: Failed to register process protection\n");
    }

    DbgLog("Driver loaded successfully\n");
    DbgLog("Device: %ws\n", deviceNameBuffer);
    DbgLog("DosDevice: %ws\n", dosNameBuffer);

    return STATUS_SUCCESS;

Cleanup:
    IoDeleteSymbolicLink(&dosDeviceName);
    IoDeleteDevice(g_Context->DeviceObject);
    ExFreePoolWithTag(g_Context, TAG_POOL);
    g_Context = NULL;
    return status;
}