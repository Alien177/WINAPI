#include "pch.h"
#include "image.h"

std::uintptr_t getImageSectionByName(const std::uintptr_t imageBase, const char* sectionName, size_t* sizeOut)
{
	if (reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_magic != 0x5A4D) {
		KdPrint(("[-] Not valid MZ header.\n"));
		return {};
	}

	const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
	const auto sectionCount = ntHeader->FileHeader.NumberOfSections;
	auto sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

	for (size_t i{}; i < sectionCount; ++i, ++sectionHeader) {
		if (!strcmp(sectionName, reinterpret_cast<const char*>(sectionHeader->Name))) {
			if (sizeOut)
				KdPrint(("[+] Section size: 0x%08X, section address: 0x%p\n", sectionHeader->Misc.VirtualSize, imageBase + sectionHeader->VirtualAddress));
				*sizeOut = sectionHeader->Misc.VirtualSize;
			return imageBase + sectionHeader->VirtualAddress;
		}
	}

	return {};
}