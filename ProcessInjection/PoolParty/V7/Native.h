#pragma once

#include <vector>
#include <Windows.h>
#include <winternl.h>

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
	PVOID KeyContext;
	PVOID ApcContext;
	IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, * PFILE_IO_COMPLETION_INFORMATION;

typedef struct _FILE_COMPLETION_INFORMATION {
	HANDLE Port;
	PVOID  Key;
} FILE_COMPLETION_INFORMATION, * PFILE_COMPLETION_INFORMATION;


typedef struct _ALPC_PORT_ATTRIBUTES
{
	unsigned long Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	unsigned __int64 MaxMessageLength;
	unsigned __int64 MemoryBandwidth;
	unsigned __int64 MaxPoolUsage;
	unsigned __int64 MaxSectionSize;
	unsigned __int64 MaxViewSize;
	unsigned __int64 MaxTotalSectionSize;
	ULONG DupObjectTypes;
#ifdef _WIN64
	ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			USHORT DataLength;
			USHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			USHORT Type;
			USHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
		ULONG CallbackId; // only valid for LPC_REQUEST messages
	};
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE {
	PORT_MESSAGE PortHeader;
	BYTE PortMessage[1000]; // Hard limit for this is 65488. An Error is thrown if AlpcMaxAllowedMessageLength() is exceeded
} ALPC_MESSAGE, * PALPC_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	ULONG AllocatedAttributes;
	ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ASSOCIATE_COMPLETION_PORT
{
	PVOID CompletionKey;
	HANDLE CompletionPort;
} ALPC_PORT_ASSOCIATE_COMPLETION_PORT, * PALPC_PORT_ASSOCIATE_COMPLETION_PORT;

typedef struct _T2_SET_PARAMETERS_V0
{
	ULONG Version;
	ULONG Reserved;
	LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, * PT2_SET_PARAMETERS;

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
	HANDLE HandleValue;
	ULONG_PTR HandleCount;
	ULONG_PTR PointerCount;
	ACCESS_MASK GrantedAccess;
	ULONG ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef enum
{
	SeDebugPrivilege = 20
} PRIVILEGES;

typedef enum
{
	AlpcAssociateCompletionPortInformation = 2
} ALPC_PORT_INFOCLASS;

typedef enum
{
	FileReplaceCompletionInformation = 61
} FILE_INFOCLASS;

typedef enum
{
	ProcessHandleInformation = 51
} PROCESS_INFOCLASS;