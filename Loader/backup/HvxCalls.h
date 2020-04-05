#pragma once
#include "stdafx.h"

typedef unsigned __int64 QWORD;

typedef enum _PEEK_POKE_TYPE {
	PEEK_BYTE  = 0,
	PEEK_WORD  = 1,
	PEEK_DWORD = 2,
	PEEK_QWORD = 3,
	PEEK_BYTES = 4,
	POKE_BYTE  = 5,
	POKE_WORD  = 6,
	POKE_DWORD = 7,
	POKE_QWORD = 8,
	POKE_BYTES = 9,
	PEEK_SPR   = 10
} PEEK_POKE_TYPE;
	
#define HvPeekPokeExpID 0x48565050
	
namespace Hvx
{
	extern LPCSTR KeysExecutePayloadFile;
	extern LPCSTR KeysExecuteRespFile;

	QWORD HvGetVersion(DWORD magic, DWORD mode, UINT64 dest, UINT64 src, UINT32 len, UINT64 arg_r8 = NULL);
	QWORD HvPostOutput(WORD code);
	QWORD HvShadowboot();	// use to hang entire console. Directs to a MACHINE_CHECK failure
	QWORD HvKeysGetStatus();
	QWORD HvKeysExecute(PBYTE CodeBlock, DWORD BufferSize, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4);
	QWORD HvGetProtectedFlags();

	DWORD ExecutePayload(BYTE* Payload, DWORD Size, PVOID Arg1, PVOID Arg2, PVOID Arg3, PVOID Arg4);

	HRESULT InitializeHvPeekPoke();

	BYTE    HvPeekBYTE(QWORD Address);
	WORD    HvPeekWORD(QWORD Address);
	DWORD   HvPeekDWORD(QWORD Address);
	QWORD   HvPeekQWORD(QWORD Address);
	HRESULT HvPeekBytes(QWORD Address, PVOID Buffer, DWORD Size);

	HRESULT HvPokeBYTE(QWORD Address, BYTE Value);
	HRESULT HvPokeWORD(QWORD Address, WORD Value);
	HRESULT HvPokeDWORD(QWORD Address, DWORD Value);
	HRESULT HvPokeQWORD(QWORD Address, QWORD Value);
	HRESULT HvPokeBytes(QWORD Address, PVOID Buffer, DWORD Size);
	VOID writeHVPriv(BYTE* src, UINT64 dest, DWORD size);
}