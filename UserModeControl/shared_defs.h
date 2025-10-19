#pragma once

// ==================== DETECT BUILD MODE ====================

#if defined(_NTDDK_) || defined(_NTIFS_) || defined(_WDMDDK_)
#define IS_KERNEL_BUILD 1
#else
#define IS_KERNEL_BUILD 0
#endif

// ==================== IOCTL DEFINITIONS ====================
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
    unsigned char Buffer[1];
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
    UCHAR Buffer[1];
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