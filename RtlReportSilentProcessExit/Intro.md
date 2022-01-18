Need to dump lsass.exe?
 
Well one way to accomplish this is to call ntdll.dll function RtlReportSilentProcessExit which will result in Windows Error Reporting service (WerFault.exe) creating a dump for you.

However you will need a couple of registry keys first:
1. `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` value `GlobalFlag` must be set to include flag `FLG_MONITOR_SILENT_PROCESS_EXIT(0x200)`
2. `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit` value `ReportingMode` must be set to `LOCAL_DUMP(0x2)`
3. `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit` value `LocalDumpFolder` could be set to a custom directory where you want you dump file to go.
If you don't set this value the dump will be created under default `%TEMP%\Silent Process Exit` directory
4. `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit` value `DumpType` could be set to `MiniDumpWithFullMemory(0x2)` unless you want some other type of mem dump

Once the registry is all set up you need to make sure you have SeDebugPrivilege and you can get a handle to the process of interest (lsass.exe in this case) with the proper access.
When you need to locate the address of ntdll!RtlReportSilentProcessExit using GetProcAddress && GetModuleHandle and pass it the lsass.exe's handle.

The End. 

```c++
NTSTATUS(NTAPI* RtlReportSilentProcessExit) (
  _In_ HANDLE hProcess,
  _In_ NTSTATUS ExitStatus);
```


References:
https://chowdera.com/2021/04/20210402154045817a.html
https://www.programmerall.com/article/78082011986/
https://www.hexacorn.com/blog/2019/09/19/silentprocessexit-quick-look-under-the-hood/
https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before-part-2
