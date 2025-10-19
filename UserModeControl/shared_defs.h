#pragma once

#pragma pack(push, 1)

#if defined(_NTDDK_) || defined(_NTIFS_) || defined(_WDMDDK_)
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

#include <Windows.h>

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) ( \
        ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
    )
#endif

#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

#define IOCTL_BASE 0x8000
#define IOCTL_SET_TARGET       CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENABLE_MONITOR   CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_MEMORY      CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY     CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE       CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INSTALL_HOOK     CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_HOOK      CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_PROCESS     CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT_PROCESS  CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)

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