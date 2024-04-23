Nothing new here. The main idea is to unhook NtReadVirtualMemory before calling MiniDumpWriteDump since some EDRs block memory access to certain processes 
using hooked NtReadVirtualMemory.
