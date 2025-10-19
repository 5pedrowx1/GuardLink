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

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <TlHelp32.h>
#include "shared_defs.h"

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
    printf("\n");
    for (SIZE_T i = 0; i < size; i++) {
        if (i % 16 == 0) {
            if (i > 0) printf("\n");
            printf("  %04zX: ", i);
        }
        printf("%02X ", bytes[i]);
    }
    printf("\n\n");
}

void ClearScreen() {
    system("cls");
}

// ==================== DRIVER CLASS ====================

class DriverInterface {
private:
    HANDLE hDriver;

    bool SendIOCTL(DWORD ioctl, const void* input, SIZE_T inputSize,
        void* output = nullptr, SIZE_T outputSize = 0,
        DWORD* bytesReturned = nullptr) {

        if (hDriver == INVALID_HANDLE_VALUE) {
            printf("[-] Driver not connected\n");
            return false;
        }

        DWORD dummy = 0;
        if (!bytesReturned) bytesReturned = &dummy;

        BOOL result = DeviceIoControl(
            hDriver,
            ioctl,
            (LPVOID)input, (DWORD)inputSize,
            output, (DWORD)outputSize,
            bytesReturned,
            nullptr
        );

        if (!result) {
            DWORD error = GetLastError();
            printf("[-] DeviceIoControl failed: %lu (0x%08X)\n", error, error);

            switch (error) {
            case ERROR_ACCESS_DENIED:
                printf("    -> Access denied - check permissions\n");
                break;
            case ERROR_INVALID_PARAMETER:
                printf("    -> Invalid parameter\n");
                break;
            case ERROR_NOT_SUPPORTED:
                printf("    -> Operation not supported\n");
                break;
            case ERROR_GEN_FAILURE:
                printf("    -> General failure\n");
                break;
            }
            return false;
        }

        return true;
    }

public:
    DriverInterface() : hDriver(INVALID_HANDLE_VALUE) {}

    ~DriverInterface() {
        Disconnect();
    }

    bool Connect(const WCHAR* devicePath = L"\\\\.\\Global\\GuardLink") {
        printf("[*] Connecting to device: %ws\n", devicePath);

        hDriver = CreateFileW(
            devicePath,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hDriver == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            printf("[-] Failed to open device: %lu (0x%08X)\n", error, error);

            if (error == ERROR_FILE_NOT_FOUND) {
                printf("    -> Device not found - is the driver loaded?\n");
            }
            else if (error == ERROR_ACCESS_DENIED) {
                printf("    -> Access denied - run as Administrator\n");
            }
            return false;
        }

        printf("[+] Connected to driver successfully\n");
        return true;
    }

    void Disconnect() {
        if (hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(hDriver);
            hDriver = INVALID_HANDLE_VALUE;
            printf("[*] Disconnected from driver\n");
        }
    }

    bool IsConnected() const {
        return hDriver != INVALID_HANDLE_VALUE;
    }

    // ==================== DRIVER OPERATIONS ====================

    bool SetTargetProcess(const WCHAR* processName) {
        printf("\n[*] Setting target process: %ws\n", processName);

        SIZE_T len = (wcslen(processName) + 1) * sizeof(WCHAR);
        bool result = SendIOCTL(IOCTL_SET_TARGET, processName, len);

        if (result) {
            printf("[+] Target process set successfully\n");
        }
        return result;
    }

    bool EnableMonitoring(bool enable) {
        printf("\n[*] %s monitoring\n", enable ? "Enabling" : "Disabling");

        BOOLEAN flag = enable ? TRUE : FALSE;
        bool result = SendIOCTL(IOCTL_ENABLE_MONITOR, &flag, sizeof(flag));

        if (result) {
            printf("[+] Monitoring %s\n", enable ? "enabled" : "disabled");
        }
        return result;
    }

    bool ReadMemory(DWORD processId, PVOID address, void* buffer, SIZE_T size) {
        printf("\n[*] Reading memory\n");
        printf("    PID:     %lu\n", processId);
        printf("    Address: 0x%p\n", address);
        printf("    Size:    %llu bytes\n", (ULONGLONG)size);

        SIZE_T requestSize = sizeof(MEMORY_OPERATION) + size;
        std::vector<BYTE> requestBuf(requestSize);
        std::vector<BYTE> responseBuf(requestSize);

        PMEMORY_OPERATION req = (PMEMORY_OPERATION)requestBuf.data();
        req->ProcessId = (HANDLE)(ULONG_PTR)processId;
        req->Address = address;
        req->Size = size;

        DWORD bytesReturned = 0;
        bool result = SendIOCTL(IOCTL_READ_MEMORY,
            req, requestSize,
            responseBuf.data(), requestSize,
            &bytesReturned);

        if (result && bytesReturned >= sizeof(MEMORY_OPERATION)) {
            PMEMORY_OPERATION resp = (PMEMORY_OPERATION)responseBuf.data();
            memcpy(buffer, resp->Buffer, size);
            printf("[+] Memory read successfully (%lu bytes returned)\n", bytesReturned);
            return true;
        }

        return false;
    }

    bool WriteMemory(DWORD processId, PVOID address, const void* buffer, SIZE_T size) {
        printf("\n[*] Writing memory\n");
        printf("    PID:     %lu\n", processId);
        printf("    Address: 0x%p\n", address);
        printf("    Size:    %llu bytes\n", (ULONGLONG)size);

        SIZE_T requestSize = sizeof(MEMORY_OPERATION) + size;
        std::vector<BYTE> requestBuf(requestSize);

        PMEMORY_OPERATION req = (PMEMORY_OPERATION)requestBuf.data();
        req->ProcessId = (HANDLE)(ULONG_PTR)processId;
        req->Address = address;
        req->Size = size;
        memcpy(req->Buffer, buffer, size);

        bool result = SendIOCTL(IOCTL_WRITE_MEMORY, req, requestSize);

        if (result) {
            printf("[+] Memory written successfully\n");
        }
        return result;
    }

    bool GetModuleBase(DWORD processId, const WCHAR* moduleName,
        PVOID* baseAddress, ULONG* moduleSize) {
        printf("\n[*] Getting module base\n");
        printf("    PID:    %lu\n", processId);
        printf("    Module: %ws\n", moduleName);

        MODULE_REQUEST req = { 0 };
        MODULE_RESPONSE resp = { 0 };

        req.ProcessId = (HANDLE)(ULONG_PTR)processId;
        wcscpy_s(req.ModuleName, moduleName);

        DWORD bytesReturned = 0;
        bool result = SendIOCTL(IOCTL_GET_MODULE,
            &req, sizeof(req),
            &resp, sizeof(resp),
            &bytesReturned);

        if (result && bytesReturned == sizeof(MODULE_RESPONSE)) {
            *baseAddress = resp.BaseAddress;
            *moduleSize = resp.Size;
            printf("[+] Module found\n");
            printf("    Base: 0x%p\n", *baseAddress);
            printf("    Size: 0x%X (%lu bytes)\n", *moduleSize, *moduleSize);
            return true;
        }

        return false;
    }

    bool InstallHook(DWORD processId, PVOID targetAddress,
        const BYTE* hookCode, ULONG hookSize) {
        printf("\n[*] Installing hook\n");
        printf("    PID:     %lu\n", processId);
        printf("    Address: 0x%p\n", targetAddress);
        printf("    Size:    %lu bytes\n", hookSize);

        if (hookSize > 16 || hookSize < 5) {
            printf("[-] Invalid hook size (must be 5-16 bytes)\n");
            return false;
        }

        HOOK_REQUEST req = { 0 };
        req.ProcessId = (HANDLE)(ULONG_PTR)processId;
        req.TargetAddress = targetAddress;
        req.HookSize = hookSize;
        memcpy(req.HookCode, hookCode, hookSize);

        printf("    Hook bytes: ");
        for (ULONG i = 0; i < hookSize; i++) {
            printf("%02X ", hookCode[i]);
        }
        printf("\n");

        bool result = SendIOCTL(IOCTL_INSTALL_HOOK, &req, sizeof(req));

        if (result) {
            printf("[+] Hook installed successfully\n");
        }
        return result;
    }

    bool RemoveHook(DWORD processId, PVOID targetAddress) {
        printf("\n[*] Removing hook\n");
        printf("    PID:     %lu\n", processId);
        printf("    Address: 0x%p\n", targetAddress);

        HOOK_REQUEST req = { 0 };
        req.ProcessId = (HANDLE)(ULONG_PTR)processId;
        req.TargetAddress = targetAddress;

        bool result = SendIOCTL(IOCTL_REMOVE_HOOK, &req, sizeof(req));

        if (result) {
            printf("[+] Hook removed successfully\n");
        }
        return result;
    }

    bool HideProcess(DWORD processId) {
        printf("\n[*] Hiding process from EPROCESS list\n");
        printf("    PID: %lu\n", processId);
        printf("[!] Warning: This uses DKOM (Direct Kernel Object Manipulation)\n");

        HANDLE pid = (HANDLE)(ULONG_PTR)processId;
        bool result = SendIOCTL(IOCTL_HIDE_PROCESS, &pid, sizeof(pid));

        if (result) {
            printf("[+] Process hidden from system\n");
            printf("    -> Will not appear in Task Manager\n");
            printf("    -> Process will continue running\n");
        }
        return result;
    }

    bool ProtectProcess(DWORD processId, const WCHAR* processName, bool enable = true) {
        printf("\n[*] %s process protection\n", enable ? "Enabling" : "Disabling");
        printf("    PID:  %lu\n", processId);
        printf("    Name: %ws\n", processName);

        PROCESS_REQUEST req = { 0 };
        req.ProcessId = (HANDLE)(ULONG_PTR)processId;
        wcscpy_s(req.ProcessName, processName);
        req.Enable = enable ? TRUE : FALSE;

        bool result = SendIOCTL(IOCTL_PROTECT_PROCESS, &req, sizeof(req));

        if (result) {
            printf("[+] Process protection %s\n", enable ? "enabled" : "disabled");
            printf("    -> Access rights stripped via ObCallbacks\n");
            printf("    -> Cannot be terminated/read/written externally\n");
        }
        return result;
    }
};

// ==================== MENU INTERFACE ====================

void PrintBanner() {
    printf("\n");
    printf("========================================\n");
    printf("     GuardLink Driver Controller       \n");
    printf("       Kernel-Mode Security Suite      \n");
    printf("========================================\n");
}

void PrintMenu() {
    printf("\n");
    printf("======== MAIN MENU ========\n");
    printf(" 1.  Set Target Process\n");
    printf(" 2.  Enable/Disable Monitoring\n");
    printf(" 3.  Read Process Memory\n");
    printf(" 4.  Write Process Memory\n");
    printf(" 5.  Get Module Base Address\n");
    printf(" 6.  Install Function Hook\n");
    printf(" 7.  Remove Function Hook\n");
    printf(" 8.  Hide Process (DKOM)\n");
    printf(" 9.  Protect Process (ObCallbacks)\n");
    printf(" 10. List Running Processes\n");
    printf(" 11. Test Driver Connection\n");
    printf(" 0.  Exit\n");
    printf("===========================\n");
    printf("Choice: ");
}

void ListProcesses() {
    printf("\n[*] Enumerating running processes...\n\n");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create snapshot\n");
        return;
    }

    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry);

    printf("%-8s %-40ws\n", "PID", "Process Name");
    printf("------------------------------------------------------------\n");

    if (Process32FirstW(snapshot, &entry)) {
        do {
            printf("%-8lu %-40ws\n", entry.th32ProcessID, entry.szExeFile);
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    printf("\n");
}

// ==================== MAIN APPLICATION ====================

int main() {
    ClearScreen();
    PrintBanner();

    // Check admin privileges
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    if (!isAdmin) {
        printf("\n[!] WARNING: Not running as Administrator\n");
        printf("    Some operations may fail. Please run as Admin.\n\n");
    }

    // Initialize driver interface
    DriverInterface driver;

    printf("\n[*] Attempting to connect to driver...\n");
    if (!driver.Connect()) {
        printf("\n[-] Failed to connect to driver\n");
        printf("[!] Make sure:\n");
        printf("    1. Driver is loaded (sc start GuardLink)\n");
        printf("    2. Running as Administrator\n");
        printf("    3. Device path is correct\n");
        printf("\n[*] Press any key to exit...\n");
        getchar();
        return 1;
    }

    printf("\n[+] Successfully connected to driver!\n");
    printf("[*] Ready for operations\n");

    // Main loop
    while (true) {
        PrintMenu();

        int choice;
        if (scanf_s("%d", &choice) != 1) {
            while (getchar() != '\n');
            printf("[-] Invalid input\n");
            continue;
        }
        while (getchar() != '\n');

        switch (choice) {
        case 1: { // Set Target Process
            WCHAR processName[260];
            printf("\nEnter target process name (e.g., notepad.exe): ");
            if (wscanf_s(L"%259s", processName, 260) == 1) {
                driver.SetTargetProcess(processName);
            }
            while (getwchar() != L'\n');
            break;
        }

        case 2: { // Enable/Disable Monitoring
            printf("\nEnable monitoring? (1=Yes, 0=No): ");
            int enable;
            if (scanf_s("%d", &enable) == 1) {
                driver.EnableMonitoring(enable != 0);
            }
            while (getchar() != '\n');
            break;
        }

        case 3: { // Read Memory
            DWORD pid;
            ULONGLONG addr;
            SIZE_T size;

            printf("\nEnter PID: ");
            scanf_s("%lu", &pid);
            printf("Enter address (hex, e.g., 7FF12345): ");
            scanf_s("%llx", &addr);
            printf("Enter size (bytes, max 4096): ");
            scanf_s("%llu", &size);
            while (getchar() != '\n');

            if (size > 4096) {
                printf("[-] Size too large (max 4096 bytes)\n");
                break;
            }

            std::vector<BYTE> buffer(size);
            if (driver.ReadMemory(pid, (PVOID)addr, buffer.data(), size)) {
                PrintMemoryHex(buffer.data(), size);
            }
            break;
        }

        case 4: { // Write Memory
            DWORD pid;
            ULONGLONG addr;
            ULONGLONG value;

            printf("\nEnter PID: ");
            scanf_s("%lu", &pid);
            printf("Enter address (hex): ");
            scanf_s("%llx", &addr);
            printf("Enter value (hex, 8 bytes max): ");
            scanf_s("%llx", &value);
            while (getchar() != '\n');

            driver.WriteMemory(pid, (PVOID)addr, &value, sizeof(value));
            break;
        }

        case 5: { // Get Module Base
            DWORD pid;
            WCHAR moduleName[260];

            printf("\nEnter PID: ");
            scanf_s("%lu", &pid);
            printf("Enter module name (e.g., kernel32.dll): ");
            wscanf_s(L"%259s", moduleName, 260);
            while (getwchar() != L'\n');

            PVOID base;
            ULONG size;
            driver.GetModuleBase(pid, moduleName, &base, &size);
            break;
        }

        case 6: { // Install Hook
            DWORD pid;
            ULONGLONG addr;

            printf("\nEnter PID: ");
            scanf_s("%lu", &pid);
            printf("Enter function address to hook (hex): ");
            scanf_s("%llx", &addr);
            while (getchar() != '\n');

            // Example: Simple JMP hook (E9 = near jump)
            BYTE hookCode[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 }; // jmp +0

            printf("\n[!] Using example hook: JMP +0 (modify as needed)\n");
            printf("[!] This will overwrite 5 bytes at target address\n");

            driver.InstallHook(pid, (PVOID)addr, hookCode, sizeof(hookCode));
            break;
        }

        case 7: { // Remove Hook
            DWORD pid;
            ULONGLONG addr;

            printf("\nEnter PID: ");
            scanf_s("%lu", &pid);
            printf("Enter hooked address (hex): ");
            scanf_s("%llx", &addr);
            while (getchar() != '\n');

            driver.RemoveHook(pid, (PVOID)addr);
            break;
        }

        case 8: { // Hide Process
            DWORD pid;
            printf("\nEnter PID to hide: ");
            scanf_s("%lu", &pid);
            while (getchar() != '\n');

            printf("\n[!] WARNING: This will unlink the process from EPROCESS list\n");
            printf("[!] The process will be invisible to Task Manager\n");
            printf("[!] Continue? (y/n): ");

            char confirm;
            scanf_s("%c", &confirm, 1);
            while (getchar() != '\n');

            if (confirm == 'y' || confirm == 'Y') {
                driver.HideProcess(pid);
            }
            else {
                printf("[*] Operation cancelled\n");
            }
            break;
        }

        case 9: { // Protect Process
            DWORD pid;
            WCHAR processName[260];

            printf("\nEnter PID: ");
            scanf_s("%lu", &pid);
            printf("Enter process name: ");
            wscanf_s(L"%259s", processName, 260);
            while (getwchar() != L'\n');

            driver.ProtectProcess(pid, processName);
            break;
        }

        case 10: { // List Processes
            ListProcesses();
            break;
        }

        case 11: { // Test Connection
            if (driver.IsConnected()) {
                printf("\n[+] Driver connection is ACTIVE\n");
                printf("    Status: Connected and ready\n");
            }
            else {
                printf("\n[-] Driver connection is INACTIVE\n");
            }
            break;
        }

        case 0: { // Exit
            printf("\n[*] Exiting...\n");
            return 0;
        }

        default:
            printf("\n[-] Invalid choice\n");
            break;
        }

        printf("\n[*] Press Enter to continue...");
        getchar();
        ClearScreen();
        PrintBanner();
    }

    return 0;
}