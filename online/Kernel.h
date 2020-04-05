#define _KERNEL_DEFINES_H

// ENABLE THIS TO OUTPUT DEBUG STUFFS
//#define DEBUG_MSG

#include "types.h"

#define CONSTANT_OBJECT_STRING(s)   { strlen( s ) / sizeof( OCHAR ), (strlen( s ) / sizeof( OCHAR ))+1, s }
#define MAKE_STRING(s)   {(USHORT)(strlen(s)), (USHORT)((strlen(s))+1), s}

#define STATUS_SUCCESS	0
#define NT_EXTRACT_ST(Status)			((((ULONG)(Status)) >> 30)& 0x3)
#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status)          (NT_EXTRACT_ST(Status) == 1)
#define NT_WARNING(Status)              (NT_EXTRACT_ST(Status) == 2)
#define NT_ERROR(Status)                (NT_EXTRACT_ST(Status) == 3)

#define FILE_SYNCHRONOUS_IO_NONALERT	0x20
#define OBJ_CASE_INSENSITIVE			0x40

typedef long			NTSTATUS;
typedef ULONG			ACCESS_MASK;

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef struct _CSTRING {
	USHORT Length;
	USHORT MaximumLength;
	CONST char *Buffer;
} CSTRING, *PCSTRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef STRING			OBJECT_STRING;
typedef CSTRING			COBJECT_STRING;
typedef PSTRING			POBJECT_STRING;
typedef PCSTRING		PCOBJECT_STRING;
typedef STRING			OEM_STRING;
typedef PSTRING			POEM_STRING;
typedef CHAR			OCHAR;
typedef CHAR*			POCHAR;
typedef PSTR			POSTR;
typedef PCSTR			PCOSTR;
typedef CHAR*			PSZ;
typedef CONST CHAR*		PCSZ;
typedef STRING			ANSI_STRING;
typedef PSTRING			PANSI_STRING;
typedef CSTRING			CANSI_STRING;
typedef PCSTRING		PCANSI_STRING;
#define ANSI_NULL		((CHAR)0)     // winnt
typedef CONST UNICODE_STRING*	PCUNICODE_STRING;
#define UNICODE_NULL			((WCHAR)0) // winnt

#define OTEXT(quote) __OTEXT(quote)


typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } st;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID (NTAPI *PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );

typedef struct _OBJECT_ATTRIBUTES {
    HANDLE RootDirectory;
    POBJECT_STRING ObjectName;
    ULONG Attributes;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


// returned by a call to 'NtQueryInformationFile' with 0x22 = FileNetworkOpenInformation
typedef struct _FILE_NETWORK_OPEN_INFORMATION {
  LARGE_INTEGER  CreationTime;
  LARGE_INTEGER  LastAccessTime;
  LARGE_INTEGER  LastWriteTime;
  LARGE_INTEGER  ChangeTime;
  LARGE_INTEGER  AllocationSize;
  LARGE_INTEGER  EndOfFile;
  ULONG  FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef struct _XBOX_HARDWARE_INFO{
	DWORD Flags;
	BYTE NumberOfProcessors;
	BYTE PCIBridgeRevisionID;
	BYTE Reserved[6];
	USHORT BldrMagic;
	USHORT BldrFlags;
} XBOX_HARDWARE_INFO, *PXBOX_HARDWARE_INFO;

typedef struct _XBOX_KRNL_VERSION{
	USHORT Major; // for 360 this is always 2
	USHORT Minor; // usually 0
	USHORT Build; // current version, for example 9199
	USHORT Qfe;
} XBOX_KRNL_VERSION, *PXBOX_KRNL_VERSION;


#ifdef __cplusplus
extern "C" {
#endif

	extern PXBOX_HARDWARE_INFO XboxHardwareInfo;
	extern PXBOX_KRNL_VERSION XboxKrnlVersion;

	NTSYSAPI
	HRESULT
	NTAPI
	ObCreateSymbolicLink(
		IN		PSTRING SymbolicLinkName,
		IN		PSTRING DeviceName
		);
	
	NTSYSAPI
	HRESULT
	NTAPI
	ObDeleteSymbolicLink(
		IN		PSTRING SymbolicLinkName
		);

	NTSYSAPI
	VOID
	NTAPI
	HalReturnToFirmware(
		IN		DWORD dwPowerDownMode
		); 

	NTSYSAPI
	NTSTATUS
	NTAPI
	NtOpenFile(
		OUT		PHANDLE FileHandle,
		IN		ACCESS_MASK DesiredAccess,
		IN		POBJECT_ATTRIBUTES ObjectAttributes,
		OUT		PIO_STATUS_BLOCK IoStatusBlock,
		IN		ULONG ShareAccess,
		IN		ULONG OpenOptions
		);

	NTSYSAPI
	NTSTATUS
	NTAPI
	NtClose(
		IN		HANDLE Handle
		);

	NTSYSAPI
	NTSTATUS
	NTAPI
	NtDeviceIoControlFile(
		IN		HANDLE FileHandle,
		IN		HANDLE Event OPTIONAL,
		IN		PIO_APC_ROUTINE ApcRoutine OPTIONAL,
		IN		PVOID ApcContext OPTIONAL,
		OUT		PIO_STATUS_BLOCK IoStatusBlock,
		IN		ULONG IoControlCode,
		IN		PVOID InputBuffer OPTIONAL,
		IN		ULONG InputBufferLength,
		OUT		PVOID OutputBuffer OPTIONAL,
		IN		ULONG OutputBufferLength
		);

	DWORD __cdecl DbgPrint(char* str, ...);
	HRESULT __stdcall ObCreateSymbolicLink( STRING*, STRING*);
	HRESULT __stdcall ObDeleteSymbolicLink( STRING* );

	// ie XexGetModuleHandle("xam.xex", &hand), returns 0 on success
	NTSYSAPI
	DWORD
	NTAPI
	XexGetModuleHandle(
	   IN		PSZ moduleName,
	   IN OUT	PHANDLE hand
	   ); 

	// ie XexGetProcedureAddress(hand ,0x50, &addr) returns 0 on success
	NTSYSAPI
	DWORD
	NTAPI
	XexGetProcedureAddress(
	   IN		HANDLE hand,
	   IN		DWORD dwOrdinal,
	   IN		PVOID Address
	   );
#ifdef __cplusplus
}
#endif


