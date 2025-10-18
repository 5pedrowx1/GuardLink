#pragma once

#define ENCRYPTION_KEY_SIZE 32
#define MAX_COMMANDS 16

// Comandos
enum {
    CMD_SET_TARGET = 0,
    CMD_ENABLE_MONITOR = 1,
    CMD_READ_MEMORY = 2,
    CMD_WRITE_MEMORY = 3,
    CMD_GET_MODULE = 4,
    CMD_INSTALL_HOOK = 5,
    CMD_REMOVE_HOOK = 6,
    CMD_HIDE_PROCESS = 7,
    CMD_PROTECT_PROCESS = 8,
    CMD_ENUM_MODULES = 9
};

#pragma pack(push, 1)

typedef struct _DYNAMIC_IOCTL_MAP {
    unsigned long Timestamp;
    unsigned long RandomSeed;
    unsigned long CommandTable[MAX_COMMANDS];
    unsigned char XorKey[ENCRYPTION_KEY_SIZE];
} DYNAMIC_IOCTL_MAP, * PDYNAMIC_IOCTL_MAP;

typedef struct _HANDSHAKE_REQUEST {
    unsigned long ClientVersion;
    unsigned long ClientTimestamp;
    unsigned char ClientNonce[32];
} HANDSHAKE_REQUEST, * PHANDSHAKE_REQUEST;

typedef struct _HANDSHAKE_RESPONSE {
    unsigned long ServerVersion;
    unsigned long ServerTimestamp;
    unsigned char ServerNonce[32];
    DYNAMIC_IOCTL_MAP IoctlMap;
} HANDSHAKE_RESPONSE, * PHANDSHAKE_RESPONSE;

typedef struct _OBFUSCATED_REQUEST {
    unsigned long Magic;
    unsigned long CommandHash;
    unsigned long PayloadSize;
    unsigned long Checksum;
    unsigned long Padding[4];
    unsigned char EncryptedPayload[1];
} OBFUSCATED_REQUEST, * POBFUSCATED_REQUEST;

#if defined(_NTDDK_) || defined(_NTIFS_) || defined(_WDMDDK_)

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
#include <Windows.h>

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