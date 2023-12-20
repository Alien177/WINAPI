APIs:

1. OpenProcess
2. NtQueryInformationProcess
3. DuplicateHandle
4. NtQueryObject -> `IoCompletion`
5. VirtualAllocEx in target process with RWX
6. WriteProcessMemory
7. CreateThreadpoolWait
8. VirtualAllocEx in target process with RW
9. WriteProcessMemory
10. VirtualAllocEx in target process with RW
11. WriteProcessMemory
12. CreateEvent
13. ZwAssociateWaitCompletionPacket
14. SetEvent - triggers execution
