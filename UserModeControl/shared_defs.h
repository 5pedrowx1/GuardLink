// Definições compartilhadas entre Driver (Kernel) e Client (Usermode)

#include <ntdef.h>
#include <ntifs.h>

// Garantir definições de direitos de acesso a processos (se não vierem dos headers do SDK)
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                  0x0001
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION               0x0008
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ                    0x0010
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE                   0x0020
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION          0x0400
#endif

#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME             0x0800
#endif

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION  0x1000
#endif


#ifndef SHARED_DEFS_H
#define SHARED_DEFS_H

// ==================== CONFIGURAÇÃO ====================

#define DEVICE_NAME_SEED 0x4D2F8A3C
#define DOS_NAME_SEED 0x7B9E1D5A
#define ENCRYPTION_KEY_SIZE 32
#define MAX_COMMANDS 16

// ==================== ESTRUTURAS DE COMUNICAÇÃO ====================

#pragma pack(push, 1)

// Mapa de IOCTLs dinâmicos
typedef struct _DYNAMIC_IOCTL_MAP {
    ULONG Timestamp;                    // Timestamp de criação
    ULONG RandomSeed;                   // Seed aleatório
    ULONG CommandTable[MAX_COMMANDS];   // Tabela de comandos ofuscados
    UCHAR XorKey[ENCRYPTION_KEY_SIZE];  // Chave XOR para payloads
} DYNAMIC_IOCTL_MAP, * PDYNAMIC_IOCTL_MAP;

// Request ofuscado
typedef struct _OBFUSCATED_REQUEST {
    ULONG Magic;            // Magic number time-based
    ULONG CommandHash;      // Hash do comando da tabela
    ULONG PayloadSize;      // Tamanho do payload
    ULONG Checksum;         // Checksum do payload
    ULONG Padding[4];       // Padding aleatório
    UCHAR EncryptedPayload[1]; // Payload criptografado (tamanho variável)
} OBFUSCATED_REQUEST, * POBFUSCATED_REQUEST;

// Handshake
typedef struct _HANDSHAKE_REQUEST {
    ULONG ClientVersion;    // Versão do cliente
    ULONG ClientTimestamp;  // Timestamp do cliente
    UCHAR ClientNonce[32];  // Nonce aleatório
} HANDSHAKE_REQUEST, * PHANDSHAKE_REQUEST;

typedef struct _HANDSHAKE_RESPONSE {
    ULONG ServerVersion;    // Versão do servidor
    ULONG ServerTimestamp;  // Timestamp do servidor
    DYNAMIC_IOCTL_MAP IoctlMap; // Mapa de IOCTLs
    UCHAR ServerNonce[32];  // Nonce do servidor
} HANDSHAKE_RESPONSE, * PHANDSHAKE_RESPONSE;

// ==================== ESTRUTURAS DE COMANDOS ====================

// Operação de memória (Read/Write)
typedef struct _MEMORY_OPERATION {
    HANDLE ProcessId;       // PID do processo alvo
    PVOID Address;          // Endereço de memória
    SIZE_T Size;            // Tamanho da operação
    UCHAR Buffer[1];        // Buffer de dados (tamanho variável)
} MEMORY_OPERATION, * PMEMORY_OPERATION;

// Request de módulo
typedef struct _MODULE_REQUEST {
    HANDLE ProcessId;       // PID do processo
    WCHAR ModuleName[260];  // Nome do módulo (ex: kernel32.dll)
} MODULE_REQUEST, * PMODULE_REQUEST;

// Response de módulo
typedef struct _MODULE_RESPONSE {
    PVOID BaseAddress;      // Endereço base do módulo
    ULONG Size;             // Tamanho do módulo
} MODULE_RESPONSE, * PMODULE_RESPONSE;

// Request de hook
typedef struct _HOOK_REQUEST {
    HANDLE ProcessId;       // PID do processo
    PVOID TargetAddress;    // Endereço alvo do hook
    ULONG HookSize;         // Tamanho do hook (5-16 bytes)
    UCHAR HookCode[16];     // Código do hook
} HOOK_REQUEST, * PHOOK_REQUEST;

// Request de processo
typedef struct _PROCESS_REQUEST {
    HANDLE ProcessId;       // PID do processo
    WCHAR ProcessName[260]; // Nome do processo
    BOOLEAN Enable;         // Habilitar/Desabilitar
} PROCESS_REQUEST, * PPROCESS_REQUEST;

#pragma pack(pop)

// ==================== ÍNDICES DE COMANDOS ====================

typedef enum _COMMAND_INDEX {
    CMD_SET_TARGET = 0,         // Define processo alvo
    CMD_ENABLE_MONITOR = 1,     // Ativa/desativa monitoramento
    CMD_READ_MEMORY = 2,        // Lê memória de processo
    CMD_WRITE_MEMORY = 3,       // Escreve memória de processo
    CMD_GET_MODULE = 4,         // Obtém base de módulo
    CMD_INSTALL_HOOK = 5,       // Instala inline hook
    CMD_REMOVE_HOOK = 6,        // Remove hook
    CMD_HIDE_PROCESS = 7,       // Esconde processo (DKOM)
    CMD_PROTECT_PROCESS = 8,    // Protege processo (ObCallbacks)
    CMD_ENUM_MODULES = 9,       // Enumera módulos (não implementado)
    CMD_MAX = MAX_COMMANDS
} COMMAND_INDEX;

// ==================== CÓDIGOS DE IOCTL ====================

// IOCTL especial para handshake (não ofuscado)
#define IOCTL_HANDSHAKE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IOCTL genérico para comandos ofuscados
#define IOCTL_GENERIC_COMMAND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ==================== FUNÇÕES AUXILIARES INLINE ====================

#ifdef __cplusplus
extern "C" {
#endif

    // Calcula hash de string (case-insensitive)
    static __forceinline ULONG CalculateHashInline(const WCHAR* str) {
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

    // Calcula checksum de buffer
    static __forceinline ULONG CalculateChecksumInline(UCHAR* data, ULONG size) {
        ULONG hash = 0x811C9DC5;
        for (ULONG i = 0; i < size; i++) {
            hash ^= data[i];
            hash *= 0x01000193;
        }
        return hash;
    }

    // Criptografia XOR
    static __forceinline void XorEncryptDecryptInline(UCHAR* data, ULONG dataSize, UCHAR* key, ULONG keySize) {
        if (!data || !key || keySize == 0) return;

        for (ULONG i = 0; i < dataSize; i++) {
            data[i] ^= key[i % keySize];
        }
    }

    // Gera nome aleatório de dispositivo
    static __forceinline void GenerateRandomDeviceNameInline(WCHAR* buffer, ULONG bufferSize, ULONG seed) {
        const WCHAR* chars = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        ULONG charCount = 62; // strlen(chars)

#ifdef _KERNEL_MODE
        LARGE_INTEGER time;
        KeQuerySystemTime(&time);
        seed ^= (ULONG)(time.QuadPart & 0xFFFFFFFF);
#else
        seed ^= (ULONG)GetTickCount();
#endif

        buffer[0] = L'\0';

        for (ULONG i = 0; i < 12; i++) {
            seed = (seed * 1103515245 + 12345);
            ULONG index = (seed >> 16) % charCount;
            buffer[i] = chars[index];
        }
        buffer[12] = L'\0';
    }

#ifdef __cplusplus
}
#endif

// ==================== MACROS DE VALIDAÇÃO ====================

// Valida se tamanho de request é válido
#define VALIDATE_REQUEST_SIZE(request, minSize) \
    ((request) != NULL && (minSize) <= sizeof(*(request)))

// Valida magic number time-based
#define CALCULATE_MAGIC_NUMBER() \
    (((ULONG)(GetTickCount64() / 1000 / 60)) ^ 0xDEADBEEF)

// Valida checksum
#define VALIDATE_CHECKSUM(data, size, expected) \
    (CalculateChecksumInline((UCHAR*)(data), (size)) == (expected))

// ==================== CONSTANTES ====================

// Versões
#define PROTOCOL_VERSION 1

// Timeouts
#define HANDSHAKE_TIMEOUT_SECONDS 30
#define COMMAND_ROTATION_SECONDS 300  // 5 minutos

// Limites
#define MAX_PAYLOAD_SIZE 4096
#define MAX_HOOK_SIZE 16
#define MIN_HOOK_SIZE 5
#define MAX_MODULE_NAME_LENGTH 260
#define MAX_PROCESS_NAME_LENGTH 260

// Status codes customizados
#define STATUS_CUSTOM_BASE 0xE0000000
#define STATUS_INVALID_MAGIC (STATUS_CUSTOM_BASE | 0x0001)
#define STATUS_INVALID_CHECKSUM (STATUS_CUSTOM_BASE | 0x0002)
#define STATUS_COMMAND_ROTATION_REQUIRED (STATUS_CUSTOM_BASE | 0x0003)

// ==================== DEBUGGING ====================

#ifdef _DEBUG
#ifdef _KERNEL_MODE
#define DEBUG_PRINT(fmt, ...) \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[StealthDrv] " fmt, __VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) \
            printf("[StealthClient] " fmt, __VA_ARGS__)
#endif
#else
#define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

#endif // SHARED_DEFS_H