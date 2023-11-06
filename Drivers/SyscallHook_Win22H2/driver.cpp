#include "pch.h"
#include "syscall_hook.h"

DRIVER_UNLOAD HookTestUnload;

NTSTATUS ntCreateFileHook(PHANDLE fileHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes,
	PIO_STATUS_BLOCK ioStatusBlock, PLARGE_INTEGER allocationSize, ULONG fileAttributes,
	ULONG shareAccess, ULONG createDisposition, ULONG createOptions, PVOID eaBuffer,
	ULONG eaLength) 
{	
	KdPrint(("NtCreateFile: %ws\n", objectAttributes->ObjectName->Buffer));

	if (wcsstr(objectAttributes->ObjectName->Buffer, L"hello.txt")) {
		return STATUS_ACCESS_DENIED;
	}

	return NtCreateFile(fileHandle, desiredAccess, objectAttributes, ioStatusBlock, allocationSize, fileAttributes,
		shareAccess, createDisposition, createOptions, eaBuffer, eaLength);
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	KdPrint(("[!] " __FUNCTION__ "\n"));
	
	auto status = STATUS_SUCCESS;

	if (hookSystemCall(reinterpret_cast<std::uintptr_t>(&ntCreateFileHook), reinterpret_cast<std::uintptr_t>(&NtCreateFile))) {
		KdPrint(("[+] NtCreateFile is hooked.\n"));
	}

	DriverObject->DriverUnload = HookTestUnload;
	return status;
}

void HookTestUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	KdPrint(("[!] " __FUNCTION__ "\n"));
	UnhookSystemCall();
}