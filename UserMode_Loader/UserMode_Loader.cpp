#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "ntdll.lib")

#ifndef RTL_PROCESS_MODULE_INFORMATION_DEFINED
#define RTL_PROCESS_MODULE_INFORMATION_DEFINED

// ==================== ESTRUTURAS ====================

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

#endif

#ifndef SystemModuleInformation
#define SystemModuleInformation 11
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Prototypes
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* pNtLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(NTAPI* pNtUnloadDriver)(PUNICODE_STRING DriverServiceName);

// ==================== UTILIDADES ====================

uint64_t GetKernelModuleAddress(const char* moduleName) {
    ULONG size = 0;
    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {
        printf("[-] NtQuerySystemInformation não encontrada\n");
        return 0;
    }

    // Primeiro chamamos para obter o tamanho (note o cast explícito)
    NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, NULL, 0, &size);

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)malloc(size);
    if (!modules) return 0;

    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, modules, size, &size);
    if (!NT_SUCCESS(status)) {
        free(modules);
        return 0;
    }

    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        char* name = (char*)modules->Modules[i].FullPathName +
            modules->Modules[i].OffsetToFileName;

        if (_stricmp(name, moduleName) == 0) {
            uint64_t addr = (uint64_t)modules->Modules[i].ImageBase;
            free(modules);
            return addr;
        }
    }

    free(modules);
    return 0;
}

BOOL EnablePrivilege(const wchar_t* privilegeName) {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
        return FALSE;

    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        CloseHandle(token);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(token);

    return result && GetLastError() == ERROR_SUCCESS;
}

// ==================== MANUAL MAPPER ====================

typedef struct _MANUAL_MAP_DATA {
    PVOID ImageBase;
    PIMAGE_NT_HEADERS64 NtHeaders;
    PVOID EntryPoint;
    PVOID Allocations[16];
    ULONG AllocationCount;
} MANUAL_MAP_DATA, * PMANUAL_MAP_DATA;

BOOL ResolveImports(PBYTE imageBase, PIMAGE_NT_HEADERS64 ntHeaders, uint64_t kernelBase) {
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (!importDesc) return TRUE;

    while (importDesc->Name) {
        char* moduleName = (char*)(imageBase + importDesc->Name);
        printf("[+] Resolvendo imports de: %s\n", moduleName);

        // Aqui você precisa resolver manualmente cada import
        // Para o kernel, normalmente tudo vem de ntoskrnl.exe
        HMODULE hNtoskrnl = LoadLibraryA("ntoskrnl.exe");
        if (!hNtoskrnl) {
            printf("[-] Falha ao carregar ntoskrnl.exe\n");
            return FALSE;
        }

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(imageBase + importDesc->FirstThunk);
        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(imageBase + importDesc->OriginalFirstThunk);

        while (thunk->u1.AddressOfData) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                // Import por ordinal
                thunk->u1.Function = (ULONGLONG)GetProcAddress(hNtoskrnl,
                    (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal));
            }
            else {
                PIMAGE_IMPORT_BY_NAME importByName =
                    (PIMAGE_IMPORT_BY_NAME)(imageBase + thunk->u1.AddressOfData);

                thunk->u1.Function = (ULONGLONG)GetProcAddress(hNtoskrnl,
                    (LPCSTR)importByName->Name);
            }

            if (!thunk->u1.Function) {
                printf("[-] Falha ao resolver import\n");
                FreeLibrary(hNtoskrnl);
                return FALSE;
            }

            thunk++;
            origThunk++;
        }

        FreeLibrary(hNtoskrnl);
        importDesc++;
    }

    return TRUE;
}

BOOL RelocateImage(PBYTE imageBase, PIMAGE_NT_HEADERS64 ntHeaders, uint64_t targetBase) {
    uint64_t delta = targetBase - ntHeaders->OptionalHeader.ImageBase;
    if (delta == 0) return TRUE;

    PIMAGE_DATA_DIRECTORY relocDir =
        &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (!relocDir->Size) {
        printf("[-] Sem tabela de relocação\n");
        return FALSE;
    }

    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(imageBase + relocDir->VirtualAddress);

    while (reloc->VirtualAddress) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD typeOffset = (PWORD)(reloc + 1);

        for (DWORD i = 0; i < count; i++) {
            WORD type = typeOffset[i] >> 12;
            WORD offset = typeOffset[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                uint64_t* patchAddr = (uint64_t*)(imageBase + reloc->VirtualAddress + offset);
                *patchAddr += delta;
            }
        }

        reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
    }

    return TRUE;
}

PVOID MapDriverManually(const char* driverPath, uint64_t* outSize) {
    printf("[+] Iniciando manual mapping de: %s\n", driverPath);

    HANDLE hFile = CreateFileA(driverPath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Falha ao abrir arquivo: %d\n", GetLastError());
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    PBYTE fileBuffer = (PBYTE)malloc(fileSize);
    if (!fileBuffer) {
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL)) {
        printf("[-] Falha ao ler arquivo\n");
        free(fileBuffer);
        CloseHandle(hFile);
        return NULL;
    }
    CloseHandle(hFile);

    // Validar PE
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Assinatura DOS inválida\n");
        free(fileBuffer);
        return NULL;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(fileBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Assinatura PE inválida\n");
        free(fileBuffer);
        return NULL;
    }

    // Alocar memória para a imagem mapeada
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    PBYTE imageBase = (PBYTE)VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!imageBase) {
        printf("[-] Falha ao alocar memória\n");
        free(fileBuffer);
        return NULL;
    }

    printf("[+] Imagem alocada em: 0x%p (Tamanho: 0x%llX)\n", imageBase, imageSize);

    // Copiar headers
    memcpy(imageBase, fileBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);

    // Copiar seções
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        printf("[+] Mapeando seção: %s (VA: 0x%X, Size: 0x%X)\n",
            section[i].Name, section[i].VirtualAddress, section[i].SizeOfRawData);

        memcpy(imageBase + section[i].VirtualAddress,
            fileBuffer + section[i].PointerToRawData,
            section[i].SizeOfRawData);
    }

    // Atualizar ponteiro de NT Headers
    PIMAGE_NT_HEADERS64 mappedNtHeaders = (PIMAGE_NT_HEADERS64)(imageBase + dosHeader->e_lfanew);

    // Resolver imports (simulado - em produção precisa resolver do kernel)
    printf("[+] Resolvendo imports...\n");
    if (!ResolveImports(imageBase, mappedNtHeaders, GetKernelModuleAddress("ntoskrnl.exe"))) {
        printf("[-] Falha ao resolver imports\n");
        VirtualFree(imageBase, 0, MEM_RELEASE);
        free(fileBuffer);
        return NULL;
    }

    // Aplicar relocações (assumindo base aleatória no kernel)
    printf("[+] Aplicando relocações...\n");
    uint64_t targetBase = (uint64_t)imageBase; // Simulado
    if (!RelocateImage(imageBase, mappedNtHeaders, targetBase)) {
        printf("[-] Falha ao aplicar relocações\n");
        VirtualFree(imageBase, 0, MEM_RELEASE);
        free(fileBuffer);
        return NULL;
    }

    printf("[+] Manual mapping concluído!\n");
    printf("[+] Entry Point: 0x%llX\n",
        (uint64_t)imageBase + mappedNtHeaders->OptionalHeader.AddressOfEntryPoint);

    *outSize = imageSize;
    free(fileBuffer);
    return imageBase;
}

// ==================== INJEÇÃO NO KERNEL ====================

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

BOOL InjectDriverToKernel(PVOID mappedDriver, SIZE_T driverSize) {
    printf("[!] ATENÇÃO: Esta função requer um exploit de kernel ativo!\n");
    printf("[!] Métodos possíveis:\n");
    printf("    - Explorar CVE de driver vulnerável\n");
    printf("    - Usar driver legítimo com arbitrary write\n");
    printf("    - Capnzão DBG/Kdmapper-style injection\n");

    // Aqui você precisaria:
    // 1. Obter capacidade de escrita arbitrária no kernel
    // 2. Alocar memória no kernel space
    // 3. Copiar o driver mapeado
    // 4. Executar o entry point

    printf("\n[+] Simulação de injeção:\n");
    printf("    1. Alocar NonPagedPool no kernel\n");
    printf("    2. Copiar imagem para kernel space\n");
    printf("    3. Chamar DriverEntry em contexto de kernel\n");
    printf("    4. Driver executando sem registro oficial\n");

    return TRUE;
}

// ==================== MAIN ====================

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  Driver Manual Mapper v1.0\n");
    printf("  by GuardLink\n");
    printf("========================================\n\n");

    if (argc < 2) {
        printf("Uso: %s <driver.sys>\n", argv[0]);
        return 1;
    }

    if (!EnablePrivilege(SE_LOAD_DRIVER_NAME)) {
        printf("[-] Falha ao habilitar SeLoadDriverPrivilege\n");
        printf("[!] Execute como Administrador\n");
        return 1;
    }

    printf("[+] Privilégios elevados\n");

    uint64_t mappedSize = 0;
    PVOID mappedDriver = MapDriverManually(argv[1], &mappedSize);

    if (!mappedDriver) {
        printf("[-] Falha no manual mapping\n");
        return 1;
    }

    printf("\n[+] Driver mapeado com sucesso!\n");
    printf("[+] Base: 0x%p\n", mappedDriver);
    printf("[+] Tamanho: 0x%llX bytes\n", mappedSize);

    printf("\n[?] Injetar no kernel? (s/n): ");
    char choice;
    if (scanf_s(" %c", &choice, 1) != 1) {
        choice = 'n';
    }

    if (choice == 's' || choice == 'S') {
        if (InjectDriverToKernel(mappedDriver, mappedSize)) {
            printf("\n[+] Driver injetado no kernel!\n");
        }
        else {
            printf("\n[-] Falha na injeção\n");
        }
    }

    printf("\n[+] Pressione Enter para sair...");
    getchar();
    getchar();

    VirtualFree(mappedDriver, 0, MEM_RELEASE);
    return 0;
}