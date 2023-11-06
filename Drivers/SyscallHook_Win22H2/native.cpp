#include "pch.h"
#include "native.h"
#include "image.h"
#include "signature_scan.h"

NTSTATUS getKernelModuleByName(const char* moduleName, std::uintptr_t* moduleStart, size_t* moduleSize)
{
	KdPrint(("[!] " __FUNCTION__ "\n"));

	if (!moduleStart || !moduleSize) {
		KdPrint(("[-] Bad arguments passed.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	ULONG size{};
	ZwQuerySystemInformation(0xB, nullptr, size, &size);

	const auto listHeader = ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
	if (!listHeader) {
		KdPrint(("[-] ExAllocatePoolWithTag failed.\n"));
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	if (const auto status = ZwQuerySystemInformation(0xB, listHeader, size, &size)) {
		KdPrint(("[-] ZwQuerySystemInformation failed.\n"));
		return status;
	}

	auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Module;

	for (size_t i{}; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Count; ++i, ++currentModule)
	{
		const auto currentModuleName = reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName);
		if (!strcmp(moduleName, currentModuleName))
		{
			KdPrint(("[+] ModuleStart: 0x%p, ModuleSize: 0x%08X\n", currentModule->ImageBase, currentModule->ImageSize));

			*moduleStart = reinterpret_cast<std::uintptr_t>(currentModule->ImageBase);
			*moduleSize = currentModule->ImageSize;
			return STATUS_SUCCESS;
		}
	}
		
	return STATUS_NOT_FOUND;
}

std::uintptr_t getServiceDescriptorTable()
{
	KdPrint(("[!] " __FUNCTION__ "\n"));

	std::uintptr_t ntoskrnlBase{};
	size_t ntoskrnlSize{};
	if (!NT_SUCCESS(getKernelModuleByName("ntoskrnl.exe", &ntoskrnlBase, &ntoskrnlSize))) {
		KdPrint(("[-] getKernelModuleByName failed.\n"));
		return {};
	}

	size_t ntoskrnlTextSize{};
	const auto ntoskrnlText = getImageSectionByName(ntoskrnlBase, ".text", &ntoskrnlTextSize);
	if (!ntoskrnlText) {
		KdPrint(("[-] getImageSectionByName failed.\n"));
		return {};
	}
	
	auto keServiceDescriptorTableShadow = scanPattern(reinterpret_cast<std::uint8_t*>(ntoskrnlText), ntoskrnlTextSize,
		"\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F", "xxxxxxxxx");

	if (!keServiceDescriptorTableShadow) {
		KdPrint(("[-] scanPattern failed to located SSDT shadow.\n"));
		return {};
	}

	keServiceDescriptorTableShadow += 21;
	keServiceDescriptorTableShadow += *reinterpret_cast<std::int32_t*>(keServiceDescriptorTableShadow) + sizeof(std::int32_t);

	return keServiceDescriptorTableShadow;
}