#include <Windows.h>
#include <iostream>
#include "Structures.h"

#define OBJ_CASE_INSENSITIVE 0x00000040

typedef NTSTATUS(WINAPI* PNTOPENFILE)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG SharedAccess, ULONG OpenOptions);
typedef void (WINAPI* PRTLINITUNICODESTRING)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(WINAPI* PNTQUERYINFORMATIONFILE)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS(WINAPI* PZWQUERYEAFILE)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, PVOID EaList, ULONG EaListLength, PULONG EaIndex, BOOLEAN RestartScan);

int main()
{
    // First things first lets find all out imports
    PRTLINITUNICODESTRING pRtlInitUnicodeString = (PRTLINITUNICODESTRING)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlInitUnicodeString");
    PNTOPENFILE pNtOpenFile = (PNTOPENFILE)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtOpenFile");
    // This one is here just for fun - we don't need it for EA info output 
    PNTQUERYINFORMATIONFILE pNtQueryInformationFile = (PNTQUERYINFORMATIONFILE)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationFile");
    PZWQUERYEAFILE pZwQueryEaFile = (PZWQUERYEAFILE)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "ZwQueryEaFile");

    if (pRtlInitUnicodeString == NULL || pNtOpenFile == NULL || pNtQueryInformationFile == NULL || pZwQueryEaFile == NULL) {
        printf("[-] Go debug your imports. Looks like you messed up somewhere.\n");
        return 1;
    }

    UNICODE_STRING fileName;
    pRtlInitUnicodeString(&fileName, L"\\??\\C:\\Windows\\System32\\calc.exe");

    OBJECT_ATTRIBUTES Attr;
    ZeroMemory(&Attr, sizeof(OBJECT_ATTRIBUTES));
    InitializeObjectAttributes(&Attr, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;

    NTSTATUS result;
    result = pNtOpenFile(&hFile, FILE_READ_DATA | FILE_READ_EA, &Attr, &iosb, NULL, NULL);
    if (NT_SUCCESS(result)) {
        
        IO_STATUS_BLOCK iosb;
        FILE_EA_INFORMATION fileEaInfo;
        result = pNtQueryInformationFile(hFile, &iosb, &fileEaInfo, sizeof(FILE_EA_INFORMATION), FileEaInformation);
        if (!NT_SUCCESS(result)) {
                    printf("[-] NtQueryInformationFile failed.\n");
        }
        else {
            printf("EA full size: %d\n", fileEaInfo.EaSize);
        }

        FILE_FULL_EA_INFORMATION eaInfo;
        ZeroMemory(&eaInfo, sizeof(FILE_FULL_EA_INFORMATION));

        // 0x80000012 == STATUS_NO_MORE_EAS
        while (result != 0x80000012) {
            result = pZwQueryEaFile(hFile, &iosb, &eaInfo, sizeof(eaInfo), TRUE, NULL, 0, NULL, FALSE);
            if (eaInfo.EaValueLength != 0) {
                printf("EA name: %s, EA size: %d\n", eaInfo.EaName, eaInfo.EaValueLength);
            }
        }
    }

    CloseHandle(hFile);

    return 0;
}
