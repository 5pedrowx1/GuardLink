#pragma once

// ==================== DETECT BUILD MODE ====================
#if defined(_NTDDK_) || defined(_NTIFS_) || defined(_WDMDDK_)
#define IS_KERNEL_BUILD 1
#else
#define IS_KERNEL_BUILD 0
#endif

// ==================== INCLUDE HEADERS ====================
#if IS_KERNEL_BUILD
    // Kernel mode
#include <ntddk.h>
#include <ntstatus.h>    
#else
    // User mode
#include <Windows.h>
#endif

// ==================== STRUCTURE DEFINITIONS ====================
#pragma pack(push, 1)

#if IS_KERNEL_BUILD
    // ==================== KERNEL MODE ====================
typedef struct _MEMORY_OPERATION {
    void* ProcessId;
    void* Address;
    unsigned long long Size;
    unsigned char Buffer[4096];  // Fixed size buffer
} MEMORY_OPERATION, * PMEMORY_OPERATION;

typedef struct _MODULE_REQUEST {
    void* ProcessId;
    wchar_t ModuleName[260];
} MODULE_REQUEST, * PMODULE_REQUEST;

typedef struct _MODULE_RESPONSE {
    void* BaseAddress;
    unsigned long Size;
} MODULE_RESPONSE, * PMODULE_RESPONSE;

typedef struct _HOOK_REQUEST {
    void* ProcessId;
    void* TargetAddress;
    unsigned long HookSize;
    unsigned char HookCode[16];
} HOOK_REQUEST, * PHOOK_REQUEST;

typedef struct _PROCESS_REQUEST {
    void* ProcessId;
    wchar_t ProcessName[260];
    unsigned char Enable;
} PROCESS_REQUEST, * PPROCESS_REQUEST;

#else
    // ==================== USER MODE ====================
typedef struct _MEMORY_OPERATION {
    HANDLE ProcessId;
    PVOID Address;
    ULONGLONG Size;
    UCHAR Buffer[4096];  // Fixed size buffer
} MEMORY_OPERATION, * PMEMORY_OPERATION;

typedef struct _MODULE_REQUEST {
    HANDLE ProcessId;
    WCHAR ModuleName[260];
} MODULE_REQUEST, * PMODULE_REQUEST;

typedef struct _MODULE_RESPONSE {
    PVOID BaseAddress;
    ULONG Size;
} MODULE_RESPONSE, * PMODULE_RESPONSE;

typedef struct _HOOK_REQUEST {
    HANDLE ProcessId;
    PVOID TargetAddress;
    ULONG HookSize;
    UCHAR HookCode[16];
} HOOK_REQUEST, * PHOOK_REQUEST;

typedef struct _PROCESS_REQUEST {
    HANDLE ProcessId;
    WCHAR ProcessName[260];
    BOOLEAN Enable;
} PROCESS_REQUEST, * PPROCESS_REQUEST;

#endif

#pragma pack(pop)