#pragma once

#define InitializeObjectAttributes(p, n, a, r, s){ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// this is probably a horrible idea BUT it does the job 
#define EA_MAX_BUFFER_SIZE 4096

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLenght;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

// this is for NtQueryInformationFile
typedef enum _FILE_INFORMATION_CLASS {
	FileEaInformation = 7
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

// this is for NtQueryInformationFile
typedef struct _FILE_EA_INFORMATION {
	ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG NextEntryOffset;
	UCHAR Flags;
	UCHAR EaNameLenght;
	USHORT EaValueLength;
	CHAR EaName[EA_MAX_BUFFER_SIZE];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;
