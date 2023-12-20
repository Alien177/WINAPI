Workflow:

1. OpenProcess -> you need a handle to the target process
2. NtQueryInformationProcess -> passing to it the handle from the target process and the second argument of type PROCESSINFOCLASS is set to 51 (ProcessHandleInformation)
3. DuplicateHandle -> duplicate each handle in the loop
4. NtQueryObject -> and query its name, stop once `TpWorkerFactory` handle in the targer process has been found
5. NtQueryInformationWorkerFactory -> takes is the duplicate handle `TpWorkerFactory` from the target process
6. WriteProcessMemory -> write to the target process at the memory address `WorkerFactoryInformation.StartRoutine` which is located inside ntdll.dll of the targer process
7. NtSetInformationWorkerFactory -> triggers execution by updating the WorkerFactory ThreadMinimum value which is increased by 1
