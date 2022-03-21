`ZwQueryEaFile` routine returns info about EA values of a file.

```c++
NTSTATUS ZwQueryEaFile{
  _In_       HANDLE           FileHandle,
  _Out_      PIO_STATUS_BLOCK IoStatusBlock, // receives final completion status and other info about the requested operation
  _Out_      PVOID            Buffer, // buffer where the EA attributes are to be returned
  _In_       ULONG            Length, // buffer length
  _In_       BOOLEAN          ReturnSingleEntry, // FALSE (we need all found entries)
  _In_       PVOID            EaList, // NULL
  _In_       ULONG            EaListLength, // 0 
  _In_Opt_   PULONG           EaIndex, // NULL
  _In_       BOOLEAN          RestartStan // TRUE (scan at the first entry) FALSE (resume from the previos ZwQueryEaFile call)
};
```

```c++
typedef struct _FILE_FULL_EA_INFORMATION {
  ULONG NextEntryOffset;
  UCHAR Flags;
  UCHAR EaNameLength;
  USHORT EaValueLength;
  CHAR EaName[1];
};
```




### Comments
ULONG - 32 bit (4 bytes) unsigned integer
UCHAR - unsigned CHAR (1 byte)
USHORT - usigned SHORT (2 bytes)




### Useful Info
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
https://docs.microsoft.com/en-us/dotnet/standard/io/file-path-formats
