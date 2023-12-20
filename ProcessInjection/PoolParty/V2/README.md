Workflow:

1. OpenProcess
2. NtQueryInformationProcess (arg1 hTargetProcess, arg2 51, ...)
3. DuplicateHandle(arg1 hTargetProcess, ...) -> out hDuplicate
4. NtQueryObject(arg1 hDuplicate, ...) -> searching for hDuplicate with name `TpWorkerFactory`
5. VirtualAllocEx(arg1 hTargetProcess, ... arg5 PAGE_EXECUTE_READWRITE) -> allocate memory ShellCodeAddress in the target
6. WriteProcessMemory(arg1 hTargetProcess, arg2 ShellCodeAddress, ...)
7. NtQueryInformationWorkerFactory(arg1 hDuplicate, arg2 4, ...)
8. ReadProcessMemory(arg1 hTargetProcess, ...) -> WorkerFactory.StartParameter value read in the injecting process
9. CreateThreadpoolWork (arg1 ShellCodeAddress, ...)
10. VirtualAllocEx(arg1 hTargetProcess, ... arg5 PAGE_READWRITE) -> allocate TP_WORK struct in remote process
11. WriteProcessMemory(arg1 hTargetProcess, ...)
12. WriteProcessMemory(arg1 hTargetProcess, ...)
13. WriteProcessMemory(arg1 hTargetProcess, ...)
