Nothing new here. The main idea is to unhook NtReadVirtualMemory before calling MiniDumpWriteDump since some EDRs block memory access to certain processes 
using hooked NtReadVirtualMemory.

The entry point was set to main in VS to keep the import address table clean.

Source:
https://github.com/ajpc500/BOFs/tree/main/StaticSyscallsDump
