#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <ctime>
#include <TlHelp32.h>
#include "shared_defs.h"

// ==================== UTILITY FUNCTIONS ====================

static ULONG CalculateHash(const WCHAR* str) {
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

static ULONG CalculateChecksum(UCHAR* data, ULONG size) {
    ULONG hash = 0x811C9DC5;
    for (ULONG i = 0; i < size; i++) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}

static void XorEncryptDecrypt(UCHAR* data, ULONG dataSize, UCHAR* key, ULONG keySize) {
    if (!data || !key || keySize == 0) return;

    for (ULONG i = 0; i < dataSize; i++) {
        data[i] ^= key[i % keySize];
    }
}

static void GenerateRandomDeviceName(WCHAR* buffer, size_t bufferSize, ULONG seed) {
    const WCHAR* chars = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    ULONG charCount = (ULONG)wcslen(chars);

    LARGE_INTEGER time;
    QueryPerformanceCounter(&time);
    seed ^= (ULONG)(time.QuadPart & 0xFFFFFFFF);

    wcscpy_s(buffer, bufferSize, L"");

    for (ULONG i = 0; i < 12; i++) {
        seed = (seed * 1103515245 + 12345);
        WCHAR ch[2] = { chars[(seed >> 16) % charCount], 0 };
        wcscat_s(buffer, bufferSize, ch);
    }
}

// ==================== DRIVER CLASS ====================

class Driver {
private:
    HANDLE hDriver;
    DYNAMIC_IOCTL_MAP ioctlMap;
    bool authenticated;
    ULONG sequenceNumber;

    enum CommandIndex {
        CMD_SET_TARGET = 0,
        CMD_ENABLE_MONITOR = 1,
        CMD_READ_MEMORY = 2,
        CMD_WRITE_MEMORY = 3,
        CMD_GET_MODULE = 4,
        CMD_INSTALL_HOOK = 5,
        CMD_REMOVE_HOOK = 6,
        CMD_HIDE_PROCESS = 7,
        CMD_PROTECT_PROCESS = 8
    };

    bool SendCommand(ULONG commandIndex, const void* data, SIZE_T dataSize,
        void* outputBuffer = nullptr, SIZE_T outputSize = 0,
        DWORD* bytesReturned = nullptr) {
        if (!authenticated) {
            printf("[-] Not authenticated\n");
            return false;
        }

        // Calcula tamanho total
        SIZE_T totalSize = sizeof(OBFUSCATED_REQUEST) + dataSize;
        std::vector<BYTE> buffer(totalSize);

        POBFUSCATED_REQUEST request = (POBFUSCATED_REQUEST)buffer.data();

        // Magic number (time-based)
        LARGE_INTEGER time;
        QueryPerformanceCounter(&time);
        ULONG currentMinute = (ULONG)((GetTickCount64() / 1000) / 60);
        request->Magic = currentMinute ^ 0xDEADBEEF;

        // Command hash
        request->CommandHash = ioctlMap.CommandTable[commandIndex];

        // Payload
        request->PayloadSize = (ULONG)dataSize;
        if (data && dataSize > 0) {
            memcpy(request->EncryptedPayload, data, dataSize);
        }

        // Checksum antes de criptografar
        request->Checksum = CalculateChecksum(request->EncryptedPayload, request->PayloadSize);

        // Criptografa payload
        XorEncryptDecrypt(request->EncryptedPayload, request->PayloadSize,
            ioctlMap.XorKey, ENCRYPTION_KEY_SIZE);

        // Padding aleatório
        for (int i = 0; i < 4; i++) {
            request->Padding[i] = rand();
        }

        // Envia comando (usa IOCTL genérico)
        DWORD dummy;
        if (!bytesReturned) bytesReturned = &dummy;

        DWORD genericIoctl = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);

        BOOL result = DeviceIoControl(
            hDriver,
            genericIoctl,
            request, (DWORD)totalSize,
            outputBuffer, (DWORD)outputSize,
            bytesReturned,
            nullptr
        );

        if (!result) {
            printf("[-] DeviceIoControl failed: %lu\n", GetLastError());
            return false;
        }

        return true;
    }

public:
    Driver() : hDriver(INVALID_HANDLE_VALUE), authenticated(false), sequenceNumber(0) {
        ZeroMemory(&ioctlMap, sizeof(ioctlMap));
        srand((unsigned int)time(nullptr));
    }

    ~Driver() {
        Disconnect();
    }

    bool Connect(const WCHAR* deviceName = nullptr) {
        WCHAR finalName[256];

        if (deviceName) {
            wcscpy_s(finalName, deviceName);
        }
        else {
            // Lê do registry
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"System\\CurrentControlSet\\Services\\GuardLink\\Parameters",
                0, KEY_READ, &hKey) == ERROR_SUCCESS) {

                WCHAR regValue[256];
                DWORD size = sizeof(regValue);

                if (RegQueryValueExW(hKey, L"DeviceName", NULL, NULL,
                    (LPBYTE)regValue, &size) == ERROR_SUCCESS) {
                    swprintf_s(finalName, L"\\\\.\\%s", regValue);
                    printf("[+] Device name read from registry: %ws\n", regValue);
                }
                else {
                    printf("[-] Failed to read device name from registry\n");
                    RegCloseKey(hKey);
                    return false;
                }

                RegCloseKey(hKey);
            }
            else {
                printf("[-] Failed to open registry key\n");
                printf("[!] Make sure driver is loaded\n");
                return false;
            }
        }

        printf("[*] Connecting to device: %ws\n", finalName);

        hDriver = CreateFileW(
            finalName,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hDriver == INVALID_HANDLE_VALUE) {
            printf("[-] Failed to open device: %lu\n", GetLastError());
            return false;
        }

        printf("[+] Device opened successfully\n");
        return true;
    }

    void Disconnect() {
        if (hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(hDriver);
            hDriver = INVALID_HANDLE_VALUE;
        }
        authenticated = false;
    }

    bool IsConnected() const {
        return hDriver != INVALID_HANDLE_VALUE && authenticated;
    }

    bool PerformHandshake() {
        if (hDriver == INVALID_HANDLE_VALUE) return false;

        HANDSHAKE_REQUEST request = { 0 };
        HANDSHAKE_RESPONSE response = { 0 };

        request.ClientVersion = 1;
        request.ClientTimestamp = (ULONG)(GetTickCount64() / 1000);

        // Gera nonce
        for (int i = 0; i < 32; i++) {
            request.ClientNonce[i] = (BYTE)(rand() % 256);
        }

        DWORD bytesReturned = 0;
        DWORD handshakeIoctl = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);

        printf("[*] Performing handshake...\n");

        BOOL result = DeviceIoControl(
            hDriver,
            handshakeIoctl,
            &request, sizeof(request),
            &response, sizeof(response),
            &bytesReturned,
            nullptr
        );

        if (!result || bytesReturned != sizeof(response)) {
            printf("[-] Handshake failed: %lu\n", GetLastError());
            return false;
        }

        if (response.ServerVersion != 1) {
            printf("[-] Version mismatch\n");
            return false;
        }

        // Copia mapa de IOCTLs
        memcpy(&ioctlMap, &response.IoctlMap, sizeof(ioctlMap));
        authenticated = true;

        printf("[+] Handshake successful\n");
        printf("[+] Server timestamp: %lu\n", response.ServerTimestamp);
        printf("[+] Random seed: 0x%08X\n", ioctlMap.RandomSeed);
        printf("[+] Command table synchronized\n");

        return true;
    }

    // ==================== HIGH-LEVEL API ====================

    bool SetTargetProcess(const WCHAR* processName) {
        printf("[*] Setting target process: %ws\n", processName);

        size_t len = wcslen(processName) + 1;
        return SendCommand(CMD_SET_TARGET, processName, len * sizeof(WCHAR));
    }

    bool EnableMonitoring(bool enable) {
        printf("[*] %s monitoring\n", enable ? "Enabling" : "Disabling");

        BOOLEAN flag = enable ? TRUE : FALSE;
        return SendCommand(CMD_ENABLE_MONITOR, &flag, sizeof(flag));
    }

    bool ReadMemory(DWORD processId, PVOID address, void* buffer, SIZE_T size) {
        printf("[*] Reading memory: PID=%lu, Addr=%p, Size=%llu\n",
            processId, address, (ULONGLONG)size);

        SIZE_T requestSize = sizeof(MEMORY_OPERATION) + size;
        std::vector<BYTE> requestBuffer(requestSize);
        std::vector<BYTE> responseBuffer(requestSize);

        PMEMORY_OPERATION request = (PMEMORY_OPERATION)requestBuffer.data();
        request->ProcessId = (HANDLE)(ULONG_PTR)processId;
        request->Address = address;
        request->Size = size;

        DWORD bytesReturned = 0;
        if (!SendCommand(CMD_READ_MEMORY, request, requestSize,
            responseBuffer.data(), (SIZE_T)requestSize, &bytesReturned)) {
            return false;
        }

        PMEMORY_OPERATION response = (PMEMORY_OPERATION)responseBuffer.data();
        memcpy(buffer, response->Buffer, size);

        printf("[+] Memory read successfully\n");
        return true;
    }

    bool WriteMemory(DWORD processId, PVOID address, const void* buffer, SIZE_T size) {
        printf("[*] Writing memory: PID=%lu, Addr=%p, Size=%llu\n",
            processId, address, (ULONGLONG)size);

        SIZE_T requestSize = sizeof(MEMORY_OPERATION) + size;
        std::vector<BYTE> requestBuffer(requestSize);

        PMEMORY_OPERATION request = (PMEMORY_OPERATION)requestBuffer.data();
        request->ProcessId = (HANDLE)(ULONG_PTR)processId;
        request->Address = address;
        request->Size = size;
        memcpy(request->Buffer, buffer, size);

        if (!SendCommand(CMD_WRITE_MEMORY, request, requestSize)) {
            return false;
        }

        printf("[+] Memory written successfully\n");
        return true;
    }

    bool GetModuleBase(DWORD processId, const WCHAR* moduleName,
        PVOID* baseAddress, ULONG* moduleSize) {
        printf("[*] Getting module base: %ws\n", moduleName);

        MODULE_REQUEST request = { 0 };
        MODULE_RESPONSE response = { 0 };

        request.ProcessId = (HANDLE)(ULONG_PTR)processId;
        wcscpy_s(request.ModuleName, moduleName);

        DWORD bytesReturned = 0;
        if (!SendCommand(CMD_GET_MODULE, &request, sizeof(request),
            &response, sizeof(response), &bytesReturned)) {
            return false;
        }

        *baseAddress = response.BaseAddress;
        *moduleSize = response.Size;

        printf("[+] Module found: Base=%p, Size=0x%X\n", *baseAddress, *moduleSize);
        return true;
    }

    bool InstallHook(DWORD processId, PVOID targetAddress,
        const BYTE* hookCode, ULONG hookSize) {
        printf("[*] Installing hook at %p (size=%lu)\n", targetAddress, hookSize);

        if (hookSize > 16 || hookSize < 5) {
            printf("[-] Invalid hook size\n");
            return false;
        }

        HOOK_REQUEST request = { 0 };
        request.ProcessId = (HANDLE)(ULONG_PTR)processId;
        request.TargetAddress = targetAddress;
        request.HookSize = hookSize;
        memcpy(request.HookCode, hookCode, hookSize);

        if (!SendCommand(CMD_INSTALL_HOOK, &request, sizeof(request))) {
            return false;
        }

        printf("[+] Hook installed successfully\n");
        return true;
    }

    bool RemoveHook(DWORD processId, PVOID targetAddress) {
        printf("[*] Removing hook from %p\n", targetAddress);

        struct {
            HANDLE ProcessId;
            PVOID Address;
        } request;

        request.ProcessId = (HANDLE)(ULONG_PTR)processId;
        request.Address = targetAddress;

        if (!SendCommand(CMD_REMOVE_HOOK, &request, sizeof(request))) {
            return false;
        }

        printf("[+] Hook removed successfully\n");
        return true;
    }

    bool HideProcess(DWORD processId) {
        printf("[*] Hiding process: PID=%lu\n", processId);

        HANDLE pid = (HANDLE)(ULONG_PTR)processId;
        if (!SendCommand(CMD_HIDE_PROCESS, &pid, sizeof(pid))) {
            return false;
        }

        printf("[+] Process hidden from system\n");
        return true;
    }

    bool ProtectProcess(DWORD processId, const WCHAR* processName) {
        printf("[*] Protecting process: %ws (PID=%lu)\n", processName, processId);

        PROCESS_REQUEST request = { 0 };
        request.ProcessId = (HANDLE)(ULONG_PTR)processId;
        wcscpy_s(request.ProcessName, processName);
        request.Enable = TRUE;

        if (!SendCommand(CMD_PROTECT_PROCESS, &request, sizeof(request))) {
            return false;
        }

        printf("[+] Process protection enabled\n");
        return true;
    }
};

// ==================== UTILITY FUNCTIONS ====================

DWORD GetProcessIdByName(const WCHAR* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

void PrintMemoryHex(const void* data, SIZE_T size) {
    const BYTE* bytes = (const BYTE*)data;
    for (SIZE_T i = 0; i < size; i++) {
        printf("%02X ", bytes[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (size % 16 != 0) printf("\n");
}

// ==================== MENU INTERFACE ====================

void PrintMenu() {
    printf("\n");
    printf("========================================\n");
    printf("       Stealth Driver Client v1.0      \n");
    printf("========================================\n");
    printf("1.  Set Target Process\n");
    printf("2.  Enable/Disable Monitoring\n");
    printf("3.  Read Process Memory\n");
    printf("4.  Write Process Memory\n");
    printf("5.  Get Module Base\n");
    printf("6.  Install Hook\n");
    printf("7.  Remove Hook\n");
    printf("8.  Hide Process (DKOM)\n");
    printf("9.  Protect Process (ObCallbacks)\n");
    printf("10. Test Connection\n");
    printf("0.  Exit\n");
    printf("========================================\n");
    printf("Choice: ");
}

// ==================== MAIN ====================

int main() {
    printf("========================================\n");
    printf("  Stealth Driver Client - Usermode App \n");
    printf("========================================\n\n");

    Driver driver;

    // Conecta ao driver
    if (!driver.Connect()) {
        printf("[-] Failed to connect to driver\n");
        printf("[*] Press any key to exit...\n");
        getchar();
        return 1;
    }

    // Handshake
    if (!driver.PerformHandshake()) {
        printf("[-] Handshake failed\n");
        printf("[*] Press any key to exit...\n");
        getchar();
        return 1;
    }

    printf("\n[+] Connection established successfully!\n");

    // Menu loop
    while (true) {
        PrintMenu();

        int choice;
        if (scanf_s("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }
        while (getchar() != '\n');

        printf("\n");

        switch (choice) {
        case 1: {
            WCHAR processName[260];
            printf("Enter target process name (e.g., notepad.exe): ");
            wscanf_s(L"%259s", processName, 260);
            while (getwchar() != L'\n');

            driver.SetTargetProcess(processName);
            break;
        }

        case 2: {
            printf("Enable monitoring? (1=Yes, 0=No): ");
            int enable;
            scanf_s("%d", &enable);
            while (getchar() != '\n');

            driver.EnableMonitoring(enable != 0);
            break;
        }

        case 3: {
            DWORD pid;
            ULONGLONG addr;
            SIZE_T size;

            printf("Enter PID: ");
            scanf_s("%lu", &pid);
            printf("Enter address (hex): ");
            scanf_s("%llx", &addr);
            printf("Enter size: ");
            scanf_s("%llu", &size);
            while (getchar() != '\n');

            if (size > 4096) {
                printf("[-] Size too large (max 4096)\n");
                break;
            }

            std::vector<BYTE> buffer(size);
            if (driver.ReadMemory(pid, (PVOID)addr, buffer.data(), size)) {
                printf("\nMemory dump:\n");
                PrintMemoryHex(buffer.data(), size);
            }
            break;
        }

        case 4: {
            DWORD pid;
            ULONGLONG addr;

            printf("Enter PID: ");
            scanf_s("%lu", &pid);
            printf("Enter address (hex): ");
            scanf_s("%llx", &addr);
            printf("Enter value (hex, max 8 bytes): ");

            ULONGLONG value;
            scanf_s("%llx", &value);
            while (getchar() != '\n');

            driver.WriteMemory(pid, (PVOID)addr, &value, sizeof(value));
            break;
        }

        case 5: {
            DWORD pid;
            WCHAR moduleName[260];

            printf("Enter PID: ");
            scanf_s("%lu", &pid);
            printf("Enter module name (e.g., kernel32.dll): ");
            wscanf_s(L"%259s", moduleName, 260);
            while (getwchar() != L'\n');

            PVOID base;
            ULONG size;
            driver.GetModuleBase(pid, moduleName, &base, &size);
            break;
        }

        case 6: {
            DWORD pid;
            ULONGLONG addr;

            printf("Enter PID: ");
            scanf_s("%lu", &pid);
            printf("Enter target address (hex): ");
            scanf_s("%llx", &addr);
            while (getchar() != '\n');

            // Exemplo: JMP rel32 para endereço fictício
            BYTE hookCode[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 }; // jmp +0
            driver.InstallHook(pid, (PVOID)addr, hookCode, sizeof(hookCode));
            break;
        }

        case 7: {
            DWORD pid;
            ULONGLONG addr;

            printf("Enter PID: ");
            scanf_s("%lu", &pid);
            printf("Enter hook address (hex): ");
            scanf_s("%llx", &addr);
            while (getchar() != '\n');

            driver.RemoveHook(pid, (PVOID)addr);
            break;
        }

        case 8: {
            DWORD pid;
            printf("Enter PID to hide: ");
            scanf_s("%lu", &pid);
            while (getchar() != '\n');

            driver.HideProcess(pid);
            break;
        }

        case 9: {
            DWORD pid;
            WCHAR processName[260];

            printf("Enter PID: ");
            scanf_s("%lu", &pid);
            printf("Enter process name: ");
            wscanf_s(L"%259s", processName, 260);
            while (getwchar() != L'\n');

            driver.ProtectProcess(pid, processName);
            break;
        }

        case 10: {
            if (driver.IsConnected()) {
                printf("[+] Connection is active and authenticated\n");
            }
            else {
                printf("[-] Not connected or not authenticated\n");
            }
            break;
        }

        case 0:
            printf("[*] Exiting...\n");
            return 0;

        default:
            printf("[-] Invalid choice\n");
            break;
        }

        printf("\n[*] Press Enter to continue...");
        getchar();
    }

    return 0;
}