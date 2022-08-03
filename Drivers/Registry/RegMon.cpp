#include <ntddk.h>

#define DRIVER_PREFIX "SimpleRegMon"


DRIVER_UNLOAD RegMonUnload;

NTSTATUS OnRegistryNotify(PVOID context, PVOID Arg1, PVOID Arg2);
void PushItem(LIST_ENTRY* entry);

LARGE_INTEGER RegCookie;

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {

	KdPrint((DRIVER_PREFIX "Initialized successfully\n"));

	auto status = STATUS_SUCCESS;

	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\regmon");
	bool symLinkCreated = false;

	do {

		UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\regmon");
		status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create device (0x%08X)\n", status));
			break;
		}

		status = IoCreateSymbolicLink(&symLink, &devName);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create sym link (0x%08X)\n", status));
			break;
		}
		symLinkCreated = true;

		UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"12840.788");
		status = CmRegisterCallbackEx(OnRegistryNotify, &altitude, DriverObject, nullptr, &RegCookie, nullptr);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to set registry callback (status=%08X)\n", status));
			break;
		}
	} while (false);

	if (!NT_SUCCESS(status)) {
		if (symLinkCreated) {
			IoDeleteSymbolicLink(&symLink);
		}
		if (DeviceObject) {
			IoDeleteDevice(DeviceObject);
		}
	}

	DriverObject->DriverUnload = RegMonUnload;

	return status;
}


void RegMonUnload(PDRIVER_OBJECT DriverObject) {

	KdPrint((DRIVER_PREFIX "Unload Routine called.\n"));

	CmUnRegisterCallback(RegCookie);

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\regmon");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2) {
	UNREFERENCED_PARAMETER(context);

	auto status = STATUS_SUCCESS;

	static const WCHAR machine[] = L"\\REGISTRY\\MACHINE\\SYSTEM\\";

	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)arg1) {
	case RegNtPostSetValueKey: {
		auto args = static_cast<REG_POST_OPERATION_INFORMATION*>(arg2);
		if (!NT_SUCCESS(args->Status))
			break;

		PCUNICODE_STRING name;
		if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&RegCookie, args->Object, nullptr, &name, 0))) {
			if (::wcsncmp(name->Buffer, machine, ARRAYSIZE(machine) - 1) == 0) {

				auto preInfo = (REG_SET_VALUE_KEY_INFORMATION*)args->PreInformation;
				NT_ASSERT(preInfo);

				WCHAR tempKeyName[256];
				WCHAR tempValueName[64];
				RtlZeroMemory(tempKeyName, sizeof(tempKeyName));
				RtlZeroMemory(tempValueName, sizeof(tempValueName));
				wcsncpy_s(tempKeyName, name->Buffer, name->Length / sizeof(WCHAR));
				wcsncpy_s(tempValueName, preInfo->ValueName->Buffer, preInfo->ValueName->Length / sizeof(WCHAR));

				KdPrint(("Key accessed: %ws\\%ws\n", tempKeyName, tempValueName));
			}

			CmCallbackReleaseKeyObjectIDEx(name);
		}
		break;
	}

	case RegNtPreSetValueKey: {
		auto PreArgs = static_cast<REG_SET_VALUE_KEY_INFORMATION*>(arg2);

		static const WCHAR lockedKey[] = L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\LsaExtensionConfig\\";
		PCUNICODE_STRING KeyName;
		if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&RegCookie, PreArgs->Object, nullptr, &KeyName, 0))) {

			if (::wcsncmp(KeyName->Buffer, lockedKey, ARRAYSIZE(lockedKey) - 1) == 0) {
				KdPrint((DRIVER_PREFIX "LOL Good Luck ;)\n"));
				status = STATUS_ACCESS_DENIED;
			}

			CmCallbackReleaseKeyObjectIDEx(KeyName);
		}
		break;
	}}

	return status;
}
