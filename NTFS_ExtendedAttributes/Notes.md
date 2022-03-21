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

`EaName` is an array of characters naming the EA for this entry.
The value associated with each entry follows the EaName array. That is, an EA's values are located at EaName + (EaNameLength + 1)

Test subject:
```
fsutil.exe file queryea C:\Windows\System32\calc.exe

Extended Attributes (EA) information for file C:\Windows\System32\calc.exe:

Total Ea Size: 0xf5

Ea Buffer Offset: 0
Ea Name: $KERNEL.PURGE.ESBCACHE
Ea Value Length: 60
0000:  60 00 00 00 03 00 02 0c  06 1c b9 6c 25 cd d4 01  `..........l%...
0010:  80 66 42 a5 70 73 d3 01  42 00 00 00 42 00 27 01  .fB.ps..B...B.'.
0020:  0c 80 00 00 20 b9 59 0c  e5 b1 b3 f3 77 ea a6 f4  .... .Y.....w...
0030:  55 57 4c 97 79 19 bb 78  5f 12 a4 44 be b2 7c f4  UWL.y..x_..D..|.
0040:  94 f0 cd 33 4d 1b 00 04  80 00 00 14 68 55 5f b5  ...3M.......hU_.
0050:  5b 4d 97 46 28 d4 29 ed  a7 f5 e2 82 d6 47 b4 26  [M.F(.)......G.&

Ea Buffer Offset: 80
Ea Name: $CI.CATALOGHINT
Ea Value Length: 5d
0000:  01 00 59 00 4d 69 63 72  6f 73 6f 66 74 2d 57 69  ..Y.Microsoft-Wi
0010:  6e 64 6f 77 73 2d 43 6c  69 65 6e 74 2d 46 65 61  ndows-Client-Fea
0020:  74 75 72 65 73 2d 50 61  63 6b 61 67 65 30 32 31  tures-Package021
0030:  34 7e 33 31 62 66 33 38  35 36 61 64 33 36 34 65  4~31bf3856ad364e
0040:  33 35 7e 61 6d 64 36 34  7e 7e 31 30 2e 30 2e 31  35~amd64~~10.0.1
0050:  39 30 34 31 2e 31 35 38  36 2e 63 61 74           9041.1586.cat
```


### Comments
ULONG - 32 bit (4 bytes) unsigned integer
UCHAR - unsigned CHAR (1 byte)
USHORT - usigned SHORT (2 bytes)




### Useful Info
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
https://docs.microsoft.com/en-us/dotnet/standard/io/file-path-formats
