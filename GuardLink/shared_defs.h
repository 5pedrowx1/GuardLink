#pragma once

// ==================== DETECT BUILD MODE ====================
#if defined(_NTDDK_) || defined(_NTIFS_) || defined(_WDMDDK_)
#define IS_KERNEL_BUILD 1
#else
#define IS_KERNEL_BUILD 0
#endif

// ==================== INCLUDE HEADERS ====================
#if IS_KERNEL_BUILD
#include <ntddk.h>
#include <ntstatus.h>    
#else
#include <Windows.h>
#endif

// ==================== STRUCTURE DEFINITIONS ====================
#pragma pack(push, 8)

typedef struct _MEMORY_OPERATION {
    unsigned long long ProcessId;
    unsigned long long Address;
    unsigned long long Size;
    unsigned char Buffer[4096];
} MEMORY_OPERATION, * PMEMORY_OPERATION;

typedef struct _MODULE_REQUEST {
    unsigned long long ProcessId;
    wchar_t ModuleName[260];
} MODULE_REQUEST, * PMODULE_REQUEST;

typedef struct _MODULE_RESPONSE {
    unsigned long long BaseAddress;
    unsigned long Size;
    unsigned int Padding;
} MODULE_RESPONSE, * PMODULE_RESPONSE;

typedef struct _HOOK_REQUEST {
    unsigned long long ProcessId;
    unsigned long long TargetAddress;
    unsigned long HookSize;
    unsigned char HookCode[16];
} HOOK_REQUEST, * PHOOK_REQUEST;

typedef struct _PROCESS_REQUEST {
    unsigned long long ProcessId;
    wchar_t ProcessName[260];
    unsigned char Enable;
} PROCESS_REQUEST, * PPROCESS_REQUEST;

#pragma pack(pop)