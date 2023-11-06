#include "pch.h"
#include "syscall_hook.h"
#include "native.h"
#include "image.h"
#include "signature_scan.h"

extern "C" {
	std::uintptr_t g_halpPerformanceCounter{};
	std::uintptr_t halCounterQueryRoutine{};
	std::uintptr_t circularKernelContextLogger{};
	void keQueryPerformanceCounterHook(ULONG_PTR* pStack);
	void temper();
}

std::uintptr_t systemCallHookFunction{};
std::uintptr_t targetSystemCallFunction{};
std::uintptr_t keServiceDescriptorTable{};
uintptr_t halpPerformanceCounter;

NTSTATUS modifyCKCL(ETWTRACECONTROLCODE functionCode, std::uint32_t enableFlags) {
	PCKCL_TRACE_PROPERTIES properties = reinterpret_cast<PCKCL_TRACE_PROPERTIES>(ExAllocatePool(NonPagedPool, PAGE_SIZE));
	if (!properties)
		return STATUS_INSUFFICIENT_RESOURCES;

	memset(properties, 0, PAGE_SIZE);

	properties->Wnode.BufferSize = PAGE_SIZE;
	properties->Wnode.Guid = { 0x54DEA73A, 0xED1F, 0x42A4, {0xAF, 0x71, 0x3E, 0x63, 0xD0, 0x56, 0xF1, 0x74} };
	properties->Wnode.ClientContext = 0x1;
	properties->Wnode.Flags = 0x20000;
	properties->BufferSize = sizeof(std::uint32_t);
	properties->MinimumBuffers = 2;
	properties->MaximumBuffers = 2;
	properties->LogFileMode = 0x400;
	properties->EnableFlags = enableFlags;
	properties->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");

	std::uint32_t returnSize{};

	return ZwTraceControl(functionCode, properties, PAGE_SIZE, properties, PAGE_SIZE, reinterpret_cast<PULONG>(&returnSize));
}

std::uintptr_t getCKCLContext() {
	std::uintptr_t ntoskrnlBase{};
	size_t ntoskrnlSize{};
	if (!NT_SUCCESS(getKernelModuleByName("ntoskrnl.exe", &ntoskrnlBase, &ntoskrnlSize)))
	{
		KdPrint(("[-] getKernelModuleByName failed.\n"));
		return {};
	}

	size_t ntoskrnlDataSize{};
	const auto ntoskrnlData = getImageSectionByName(ntoskrnlBase, ".data", &ntoskrnlDataSize);
	if (!ntoskrnlData)
	{
		KdPrint(("[-] getImageSectionByName failed.\n"));
		return {};
	}

	auto etwpDebuggerData = scanPattern(reinterpret_cast<std::uint8_t*>(ntoskrnlData),
		ntoskrnlDataSize, "\x2C\x08\x04\x38\x0C", "xxxxx");
	if (!etwpDebuggerData)
	{
		KdPrint(("[-] scanPattern failed to locate etwpDebuggerData.\n"));
		return {};
	}

	etwpDebuggerData -= 0x2;

	KdPrint(("[+] etwpDebuggerData located at: 0x%p\n", etwpDebuggerData));

	etwpDebuggerData = *reinterpret_cast<std::uintptr_t*>(etwpDebuggerData + 0x10);

	// The Circular Kernel Context Logger appears to always be at index 2 in the array
	const auto circularKernelContextLogger = reinterpret_cast<std::uintptr_t*>(etwpDebuggerData)[2];
	if (circularKernelContextLogger <= 1)
	{
		KdPrint(("[-] Failed to locate the CKCL logger.\n"));
		return {};
	}

	KdPrint(("[+] CKCL logger: 0x%p\n", circularKernelContextLogger));

	return circularKernelContextLogger;
}

NTSTATUS hookPerformanceCounterRoutine(std::uintptr_t hookFunction, std::uintptr_t* oldFunction)
{
	UNICODE_STRING keQueryPerformanceCounterUnicode = RTL_CONSTANT_STRING(L"KeQueryPerformanceCounter");
	const auto keQueryPerformanceCounter = reinterpret_cast<std::uintptr_t>(MmGetSystemRoutineAddress(&keQueryPerformanceCounterUnicode));

	if (!keQueryPerformanceCounter) {
		KdPrint(("[-] MmGetSystemRoutineAddress failed.\n"));
		return STATUS_NOT_FOUND;
	}

	auto halpPerformanceCounter = scanPattern(reinterpret_cast<std::uint8_t*>(keQueryPerformanceCounter), 0x100, "\xf1\x48\x8b\x3d", "xxxx");

	halpPerformanceCounter += 4;
	halpPerformanceCounter = halpPerformanceCounter + *reinterpret_cast<std::int32_t*>(halpPerformanceCounter) + 4;

	g_halpPerformanceCounter = halpPerformanceCounter;
	halCounterQueryRoutine = *reinterpret_cast<std::uintptr_t*>(*reinterpret_cast<std::uintptr_t*>(halpPerformanceCounter) + 0x70);

	KdPrint(("HalpPerformanceCounter:%p  halCounterQueryRoutine:%p\n", halpPerformanceCounter, halCounterQueryRoutine));

	*reinterpret_cast<std::uintptr_t*>(*reinterpret_cast<std::uintptr_t*>(halpPerformanceCounter) + 0x70) = reinterpret_cast<std::uintptr_t>(&temper);

	return STATUS_SUCCESS;
}

void keQueryPerformanceCounterHook(ULONG_PTR* pStack)
{
	if (ExGetPreviousMode() == KernelMode)
	{
		return;
	}

	for (size_t i = 0; i < 10; i++)
	{
		if (pStack[i] == circularKernelContextLogger)
		{
			std::uintptr_t currentThread = reinterpret_cast<std::uintptr_t>(KeGetCurrentThread());
			std::uint32_t syscallNumber = *reinterpret_cast<std::uint32_t*>(currentThread + 0x80);

			if (!syscallNumber)
				return;
			
			const auto syscallType = (syscallNumber >> 7) & 0x20;
			const auto serviceTable = *reinterpret_cast<std::int32_t**>(keServiceDescriptorTable + syscallType);
			const auto systemRoutine = reinterpret_cast<std::uintptr_t>(serviceTable) + (serviceTable[syscallNumber & 0xFFF] >> 4);
			
			auto stack = (ULONG_PTR)pStack + 0x280;

			if (*reinterpret_cast<std::uint64_t*>(stack) == systemRoutine) {
				if (systemRoutine == targetSystemCallFunction) {
					*reinterpret_cast<std::uint64_t*>(stack) = systemCallHookFunction;
				}
			}
			
			return;
		}
	}
}

bool hookSystemCall(std::uintptr_t hookFunction, std::uintptr_t systemFunction)
{
	KdPrint(("[!] " __FUNCTION__ "\n"));

	systemCallHookFunction = hookFunction; // NtCreateFileHook
	targetSystemCallFunction = systemFunction; // original NtCreateFile

	circularKernelContextLogger = getCKCLContext();
	if (!circularKernelContextLogger) {
		KdPrint(("[-] getCKCLContext failed.\n"));
		return false;
	}

	keServiceDescriptorTable = getServiceDescriptorTable();
	if (!keServiceDescriptorTable) {
		KdPrint(("[-] getServiceDescriptorTable failed.\n"));
		return false;
	}

	if (!NT_SUCCESS(modifyCKCL(EtwUpdateLoggerCode, EVENT_TRACE_FLAG_SYSTEMCALL))) {
		if (!NT_SUCCESS(modifyCKCL(EtwStartLoggerCode, EVENT_TRACE_FLAG_SYSTEMCALL))) {
			return false;
		}
		else {
			if (!NT_SUCCESS(modifyCKCL(EtwUpdateLoggerCode, EVENT_TRACE_FLAG_SYSTEMCALL))) {
				return false;
			}
		}
	}

	KdPrint(("[+] CKCL is set to log system calls and running.\n"));

	*reinterpret_cast<std::uint64_t*>(circularKernelContextLogger + Offsets::wmiGetCpuClock) = 1;

	if (!NT_SUCCESS(hookPerformanceCounterRoutine(reinterpret_cast<std::uintptr_t>(&temper), &halCounterQueryRoutine)))
	{
		KdPrint(("[-] hookPerformanceCounterRoutine failed.\n"));
		return false;
	}

	return true;
}

bool UnhookSystemCall()
{
	KdPrint(("[!] " __FUNCTION__ "\n"));

	*reinterpret_cast<std::uintptr_t*>(*reinterpret_cast<std::uintptr_t*>(g_halpPerformanceCounter) + 0x70) = halCounterQueryRoutine;
	return true;
}
