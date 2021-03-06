#include "stdafx.h"
#include "HvxCalls.h"
#pragma warning(push)
#pragma warning(disable:4826) // Get rid of the sign-extended warning

#define HvxCall QWORD _declspec(naked)

namespace Hvx
{
	namespace
	{
		const WORD cMagic = 0x4D4D;
		const WORD cVersion = 0x4099;
		const DWORD cFlags = NULL;
		const DWORD cSize = 0x120;
		const DWORD cEntryPoint = 0x120;
		const BYTE cKey[0x10] = { 0x81, 0x68, 0x4D, 0x8C, 0x90, 0xFD, 0xBF, 0x3C, 0x04, 0x2C, 0x27, 0x44, 0x79, 0xC9, 0xF5, 0x25 };
		const BYTE cSig[0x100] = { 0 };
		const DWORD cBufferSize = 0x3000;

		BYTE BLKey[0x10] = { 0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA };

		typedef struct _KeysExecute
		{
			WORD Magic;			// 0x2
			WORD Version;		// 0x2
			DWORD Flags;		// 0x4
			DWORD EntryPoint;	// 0x4
			DWORD Size;			// 0x4
			BYTE key[0x10];		// 0x10
			BYTE Sig[0x100];
			// Header: 0x20
		}KeysExecutes, *PKeysExecute;

		enum KeysExecuteError
		{
			EXECUTE_SUCCESS,
			EXECUTE_INVALID_PAYLOAD_SIZE,
			EXECUTE_INVALID_BUFFER_SIZE,
			EXECUTE_INVALID_BUFFER_ADDRESS,
			EXECUTE_INVALID_PARAMETERS
		};

		const BYTE HvPeekPokeExp[] = {
			0x48, 0x58, 0x50, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x34, 0x1F, 0xD6, 0xDA,
			0x2F, 0xCA, 0xA8, 0x17, 0xF0, 0x30, 0xCC, 0x44, 0x0A, 0x41, 0xFA, 0x7C, 0xA0, 0xC1, 0xFD, 0x33,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x7A, 0x02, 0x59, 0x43, 0x9E, 0xE6, 0x93, 0xD5, 0x01, 0xC9, 0x48, 0x4D, 0xB2, 0xBF, 0x9D, 0x18,
			0xA9, 0x16, 0x5E, 0xFF, 0x1E, 0xD5, 0xB6, 0xA8, 0x79, 0x60, 0xA8, 0x2F, 0xC1, 0x8D, 0x20, 0x8A,
			0xEB, 0x46, 0xC3, 0x01, 0xEC, 0xC4, 0xDB, 0xDF, 0xA1, 0x04, 0xD1, 0xDF, 0x23, 0x69, 0x5E, 0xCC,
			0x50, 0xC3, 0xF4, 0xDD, 0xA4, 0x80, 0x7D, 0x05, 0x2D, 0x57, 0xFF, 0x60, 0xA5, 0x58, 0x69, 0x27,
			0x9A, 0x33, 0x70, 0xE8, 0xC2, 0x82, 0xDC, 0xDA, 0xE2, 0x4D, 0xE1, 0xF8, 0xA1, 0xD2, 0xCC, 0x8D,
			0x98, 0x05, 0xD1, 0xA3, 0x2E, 0x37, 0x06, 0x0F, 0xF7, 0xEF, 0x70, 0xEF, 0x28, 0xD7, 0xAE, 0xD5,
			0x5B, 0x19, 0x1B, 0x13, 0x50, 0x0D, 0x15, 0x00, 0x92, 0x01, 0xEE, 0x38, 0xA7, 0x61, 0xB1, 0xA1,
			0x27, 0xBF, 0xB0, 0x42, 0x0F, 0x07, 0xC3, 0x8F, 0x78, 0xAD, 0xAF, 0x87, 0x8F, 0x34, 0x8A, 0xA6,
			0x69, 0x7D, 0x40, 0xB6, 0x5C, 0x9E, 0x01, 0xEC, 0x9F, 0x5E, 0x78, 0x30, 0x09, 0x5A, 0x21, 0xFF,
			0x35, 0x8C, 0x13, 0xBE, 0xBC, 0x92, 0x67, 0xE3, 0x17, 0x0B, 0x09, 0x1C, 0xE2, 0x9D, 0xEC, 0xFD,
			0xFB, 0x6C, 0x49, 0x3A, 0xCC, 0xE7, 0x99, 0xB6, 0xB3, 0x8A, 0x8F, 0xEF, 0xF7, 0xA0, 0x28, 0x4F,
			0x72, 0xC7, 0x3D, 0xD7, 0xCC, 0xEB, 0xB2, 0x1B, 0x74, 0x93, 0xD7, 0x02, 0x05, 0xD5, 0xE1, 0x25,
			0x35, 0xD7, 0xE0, 0x50, 0xEA, 0xCF, 0x82, 0x69, 0xE3, 0x3B, 0x6F, 0xFA, 0x13, 0xF0, 0x5B, 0xD9,
			0x1A, 0xB0, 0xD3, 0x0B, 0x85, 0x4D, 0x6A, 0xFC, 0x31, 0x45, 0xC3, 0xA3, 0xFA, 0x7E, 0xDA, 0x93,
			0x84, 0xD4, 0xE7, 0xFA, 0xAB, 0x7C, 0x22, 0x96, 0x54, 0x69, 0x7F, 0xC9, 0xF8, 0xC4, 0x5A, 0xC2,
			0x82, 0x99, 0x34, 0x46, 0x81, 0x6F, 0x06, 0x33, 0x19, 0x94, 0x74, 0xA4, 0x76, 0x02, 0x4F, 0xB9,
			0x48, 0x56, 0x50, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x60, 0x00, 0x00, 0x01, 0x90,
			0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00,
			0x7D, 0x88, 0x02, 0xA6, 0xFB, 0xE1, 0xFF, 0xF0, 0xF9, 0x81, 0xFF, 0xF8, 0x94, 0x21, 0xFF, 0x00,
			0x7C, 0x9F, 0x23, 0x78, 0x2C, 0x1F, 0x00, 0x00, 0x41, 0x82, 0x00, 0xC0, 0x2C, 0x1F, 0x00, 0x01,
			0x41, 0x82, 0x00, 0xC0, 0x2C, 0x1F, 0x00, 0x02, 0x41, 0x82, 0x00, 0xC0, 0x2C, 0x1F, 0x00, 0x03,
			0x41, 0x82, 0x00, 0xC0, 0x2C, 0x1F, 0x00, 0x0A, 0x41, 0x82, 0x00, 0x64, 0x2C, 0x1F, 0x00, 0x05,
			0x41, 0x82, 0x00, 0xD4, 0x2C, 0x1F, 0x00, 0x06, 0x41, 0x82, 0x00, 0xD4, 0x2C, 0x1F, 0x00, 0x07,
			0x41, 0x82, 0x00, 0xD4, 0x2C, 0x1F, 0x00, 0x08, 0x41, 0x82, 0x00, 0xD4, 0x2C, 0x1F, 0x00, 0x0B,
			0x40, 0x80, 0x00, 0x00, 0x80, 0x60, 0x00, 0x4C, 0x7C, 0x62, 0x1A, 0x14, 0x80, 0x63, 0x00, 0x08,
			0x7C, 0x69, 0x03, 0xA6, 0x7C, 0xC3, 0x33, 0x78, 0x38, 0x80, 0x00, 0x01, 0x4E, 0x80, 0x04, 0x21,
			0x7C, 0x66, 0x1B, 0x78, 0x7C, 0xE9, 0x03, 0xA6, 0x2C, 0x1F, 0x00, 0x04, 0x41, 0x82, 0x00, 0x6C,
			0x2C, 0x1F, 0x00, 0x09, 0x41, 0x82, 0x00, 0xA0, 0x48, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x05,
			0x7C, 0xA6, 0x2B, 0x78, 0x3C, 0x80, 0x7C, 0x60, 0x50, 0xA6, 0x54, 0x6A, 0x60, 0x84, 0x02, 0xA6,
			0x50, 0xC4, 0x32, 0xE8, 0x7C, 0x68, 0x02, 0xA6, 0x38, 0x63, 0x00, 0x30, 0x90, 0x83, 0x00, 0x00,
			0x7C, 0x00, 0x18, 0x6C, 0x7C, 0x00, 0x1F, 0xAC, 0x7C, 0x00, 0x04, 0xAC, 0x4C, 0x00, 0x01, 0x2C,
			0x7C, 0x79, 0x4A, 0xA6, 0x48, 0x00, 0x00, 0x98, 0x88, 0x65, 0x00, 0x00, 0x48, 0x00, 0x00, 0x90,
			0xA0, 0x65, 0x00, 0x00, 0x48, 0x00, 0x00, 0x88, 0x80, 0x65, 0x00, 0x00, 0x48, 0x00, 0x00, 0x80,
			0xE8, 0x65, 0x00, 0x00, 0x48, 0x00, 0x00, 0x78, 0x8B, 0xE5, 0x00, 0x00, 0x9B, 0xE6, 0x00, 0x00,
			0x38, 0xA5, 0x00, 0x01, 0x38, 0xC6, 0x00, 0x01, 0x42, 0x00, 0xFF, 0xF0, 0x38, 0x60, 0x00, 0x00,
			0x48, 0x00, 0x00, 0x5C, 0x98, 0xC5, 0x00, 0x00, 0x48, 0x00, 0x00, 0x40, 0xB0, 0xC5, 0x00, 0x00,
			0x48, 0x00, 0x00, 0x38, 0x90, 0xC5, 0x00, 0x00, 0x48, 0x00, 0x00, 0x30, 0xF8, 0xC5, 0x00, 0x00,
			0x48, 0x00, 0x00, 0x28, 0x8B, 0xE6, 0x00, 0x00, 0x9B, 0xE5, 0x00, 0x00, 0x7C, 0x00, 0x28, 0x6C,
			0x7C, 0x00, 0x2F, 0xAC, 0x7C, 0x00, 0x04, 0xAC, 0x4C, 0x00, 0x01, 0x2C, 0x38, 0xA5, 0x00, 0x01,
			0x38, 0xC6, 0x00, 0x01, 0x42, 0x00, 0xFF, 0xE0, 0x38, 0x60, 0x00, 0x00, 0x7C, 0x00, 0x28, 0x6C,
			0x7C, 0x00, 0x2F, 0xAC, 0x7C, 0x00, 0x04, 0xAC, 0x4C, 0x00, 0x01, 0x2C, 0x38, 0x21, 0x01, 0x00,
			0xEB, 0xE1, 0xFF, 0xF0, 0xE9, 0x81, 0xFF, 0xF8, 0x7D, 0x88, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20

		};
	}

	LPCSTR KeysExecutePayloadFile = "hdd:\\XeKeys\\KeysExecutePayload.bin";
	LPCSTR KeysExecuteRespFile = "hdd:\\XeKeys\\KeysExecuteResp.bin";

	static HvxCall HvxGetVersion(DWORD magic, DWORD mode, UINT64 dest, UINT64 src, UINT32 len, UINT64 arg_r8 = NULL)
	{
		__asm
		{
			li r0, 0 // HvxGetVersion
			sc
			blr
		}
	}

	static HvxCall HvxPostOutput(WORD code)
	{
		__asm
		{
			li	r0, 0xD
			sc
			blr
		}
	}

	static HvxCall HvxShadowboot()
	{
		__asm
		{
			li	r0, 0x21
			sc
			blr
		}
	}
	
	static HvxCall HvxKeysGetStatus()
	{
		__asm
		{
			li	r0, 0x30
			sc
			blr
		}
	}

	static HvxCall HvxKeysExecute(PBYTE Payload, DWORD BufferSize, PVOID Arg1, PVOID Arg2, PVOID Arg3, PVOID Arg4)
	{
		__asm
		{
			li	r0, 0x40
			sc
			blr
		}
	}

	static HvxCall HvxGetProtectedFlags()
	{
		__asm
		{
			li	r0, 0x59
			sc
			blr
		}
	}

	static HvxCall HvxExpansionInstall(DWORD PhysicalAddress, DWORD CodeSize) {
		__asm
		{
			li	r0, 0x70
			sc
			blr
		}
	}
	static HvxCall HvxExpansionCall(DWORD ExpansionId, QWORD Param1 = 0, QWORD Param2 = 0, QWORD Param3 = 0, QWORD Param4 = 0) {
		__asm
		{
			li	r0, 0x71
			sc
			blr
		}
	}

	QWORD HvGetVersion(DWORD magic, DWORD mode, UINT64 dest, UINT64 src, UINT32 len, UINT64 arg_r8)
	{
		return HvxGetVersion(magic, mode, dest, src, len, arg_r8);
	}

	QWORD HvPostOutput(WORD code)
	{
		return HvxPostOutput(code);
	}

	QWORD HvShadowboot()
	{
		// goodbye cruel world!
		// ba        _v_MACHINE_CHECK_0
		return HvxShadowboot();
	}

	QWORD HvKeysGetStatus()
	{
		return HvxKeysGetStatus();
	}

	QWORD HvKeysExecute(PBYTE CodeBlock, DWORD BufferSize, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4)
	{
		return HvxKeysExecute(CodeBlock, BufferSize, arg1, arg2, arg3, arg4);
	}

	QWORD HvGetProtectedFlags()
	{
		return HvxGetProtectedFlags();
	}

	// XeKeysExecute seems to be ms's official way of executing a privileged ppc block. where we use expansions, they use this.
	// If your console freezes after calling HvKeysExecute check the following:
	//		- Allocate the code block in using something like XPhysicalAlloc or MmAllocatePhysicalMemory
	//			The address must be within a certain range to be considered valid
	//		- Check your PPC, I can't protect you from bad PPC code that causes a read/write exception
	// Parameters
	//		Payload: Payload buffer
	//			- Must be 0x80 byte aligned
	//			- Must be > 0x120 and < 0x10000
	//			- Must be allocated with XPhysicalAlloc or MmAllocatePhysicalMemory
	//		BufferSize: Return buffer size
	//			- Must be > 0x120 and < 0x10000
	//			- Must be 0x80 byte aligned
	// Header Info
	//		WORD Magic: Must be 0x4D4D
	//		WORD Version: Doesn't really matter
	//		DWORD Flags: Doesn't really matter, leave null
	//		DWORD EntryPoint:
	//			- Must be after >= 0x120 and < Size
	//			- Must be 4 byte aligned
	//		DWORD Size:
	//			- Must be > 0x120 and < BufferSize
	//			- Must be 0x10 aligned
	//		BYTE Key[0x10]: key used for Rc4 encryption/decryption. rc4Key = HmacSha(header+0x10, 0x10)
	//		BYTE Sig[0x100]: Rsa signature, we patch the RSA check so this can be null without an issue
	//		PBYTE CodeBlock: Payload to be executed
	DWORD ExecutePayload(BYTE* Payload, DWORD Size, PVOID Arg1, PVOID Arg2, PVOID Arg3, PVOID Arg4)
	{
		if ((Size + cSize > cBufferSize) || (Size + cSize < 0x120))
			return EXECUTE_INVALID_PAYLOAD_SIZE;
		if (cBufferSize == 0)
			return EXECUTE_INVALID_BUFFER_SIZE;
		BYTE* bPayload = (PBYTE)XPhysicalAlloc(cBufferSize, MAXULONG_PTR, NULL, PAGE_READWRITE);
		memset(bPayload, 0, cBufferSize);

		PKeysExecute cHeader = (PKeysExecute)bPayload;
		cHeader->Magic = cMagic;
		cHeader->Version = cVersion;
		cHeader->Flags = cFlags;
		cHeader->Size = cSize + Size;
		cHeader->EntryPoint = cEntryPoint;
		memcpy(cHeader->key, cKey, 0x10);
		memcpy(cHeader->Sig, cSig, 0x100);
		memcpy(bPayload + cEntryPoint, Payload, Size);

		// data needs to be sent encrypted with the key in the header! rc4Key = HmacSha(header+0x10, 0x10)
		// you could just patch the call to XeCryptRc4Ecb as well and send it unencrypted data. but im not doing that - address: 0x6148
		XECRYPT_RC4_STATE rc4;
		//BYTE rc4Key[0x10] = { 0x25, 0xa9, 0x78, 0xae, 0x7b, 0xe9, 0x40, 0xff, 0x90, 0x90, 0x6e, 0x74, 0xa7, 0x3a, 0xad, 0xde };
		BYTE* rc4Key = (BYTE*)XPhysicalAlloc(0x10, MAXULONG_PTR, 0, PAGE_READWRITE);
		XeCryptHmacSha(BLKey, 0x10, cHeader->key, 0x10, 0, 0, 0, 0, rc4Key, 0x10);
		printf("Encrypting data...\n");
		XeCryptRc4Key(&rc4, rc4Key, 0x10);
		XeCryptRc4Ecb(&rc4, bPayload + 0x20, cHeader->Size - 0x20);
		printf("Done!\n");

		// patch the rsa check in HvxKeysExecute - allows a custom payload to be run.
		DWORD rsaPatch = 0x38600001; // li r3, 1
		Hvx::HvPokeDWORD(0x800001000000617CULL, rsaPatch);

		QWORD physPayload = 0x8000000000000000ULL + (DWORD)MmGetPhysicalAddress(bPayload);

		// The Following is a weird check done by the syscall. I've seen it trip and not trip without changing anything in the source files
		// Seems to be Heavily dependent on the address XPhysicalAlloc assigns you
		// Maybe MmAllocatePhysicalMemory is supposed to be used instead?
		// Should think about a way to free and reallocate to a different address... maybe later
		QWORD physCheck = (((physPayload + cBufferSize) - 1) ^ physPayload) & 0xFFFF0000;
		if (physCheck)
		{
			printf("PhysCheck Failed\n[physCheck: 0x%016llX][cBufferSize: 0x%X]\n", physCheck, cBufferSize);
			return EXECUTE_INVALID_BUFFER_SIZE;
		}
		if ((physPayload & 0xFFFFFFFF) > 0x1FFBFFFF)
		{
			printf("Invalid bPayload address, make sure your sending a block created with XPhysicalAlloc!\n");
			printf("physPayload: 0x%016llX\n", physPayload);
			return EXECUTE_INVALID_BUFFER_ADDRESS;
		}

		// attempt to execute challenge by syscall - HvxKeysExecute = 0x40
		DbgOut("Executing Payload...\n");
		if (Arg1)
			DbgOut("Arg1: 0x%016llX\n", Arg1);
		if (Arg2)
			DbgOut("Arg2: 0x%016llX\n", Arg2);
		if (Arg3)
			DbgOut("Arg3: 0x%016llX\n", Arg3);
		if (Arg4)
			DbgOut("Arg4: 0x%016llX\n", Arg4);
		DWORD ret = (DWORD)HvKeysExecute((PBYTE)physPayload, cBufferSize, Arg1, Arg2, Arg3, Arg4);

		// restore the rsa code
		DWORD rsaOrig = 0x48005245; // bl XeCryptBnQwBeSigVerify
		Hvx::HvPokeDWORD(0x800001000000617CULL, rsaOrig);

		if (ret != 0)
		{
			printf("ERROR: ");
			if (ret == 0xC8000030)
				printf("[%08X] Parameter Fail!\n\tPayload must be 0x80 byte aligned!\n\tSize must be greater than 0x120 and less than 0x10000 AND must be 0x80 byte aligned!\n", ret);
			else if (ret == 0xC8000032)
				printf("[%08X] Magic or Address Fail!\n\tMagic must be 0x4D4D\n", ret);
			else if (ret == 0xC8000033)
				printf("[%08X] HV Magic Fail!\n\tHV magic must be 0x4E4E\n", ret);
			else if (ret == 0xC8000034)
				printf("[%08X] Header Size Fail!\n\tSize in header must be > 0x120 AND aligned to 0x10 AND < the buffer size!\n", ret);
			else if (ret == 0xC8000035)
				printf("[%08X] EntryPoint Fail!\n\tEntrypoint must be > 0x120 AND 4 byte aligned AND < code size\n", ret);
			else if (ret == 0xC8000036)
				printf("[%08X] Crypt/Signature Fail!\n\tPatch the call to XeCryptBnQwBeSigVerify!\n", ret);
			else
				printf("ret: %08X\n", ret);
			return EXECUTE_INVALID_PARAMETERS;
		}

		// dump return buffer
		DbgOut("Dumping buffer\n");
		if (!CWriteFile(KeysExecuteRespFile, bPayload, cBufferSize))
			DbgOut("Buffer not dumped!\n");

		XPhysicalFree(bPayload);
		XPhysicalFree(rc4Key);
		return ret;
	}

	HRESULT InitializeHvPeekPoke() {

		// Allocate physcial memory for this expansion
		VOID* pPhysExp = XPhysicalAlloc(0x1000, MAXULONG_PTR, 0, PAGE_READWRITE);
		DWORD physExpAdd = (DWORD)MmGetPhysicalAddress(pPhysExp);

		// Copy over our expansion data
		ZeroMemory(pPhysExp, 0x1000);
		memcpy(pPhysExp, HvPeekPokeExp, sizeof(HvPeekPokeExp));

		// Now we can install our expansion
		HRESULT result = (HRESULT)HvxExpansionInstall(physExpAdd, 0x1000);

		// Free our allocated data
		XPhysicalFree(pPhysExp);

		// Return our install result
		return result;
	}

	BYTE    HvPeekBYTE(QWORD Address) {
		return (BYTE)HvxExpansionCall(HvPeekPokeExpID, PEEK_BYTE, Address);
	}
	WORD    HvPeekWORD(QWORD Address) {
		return (WORD)HvxExpansionCall(HvPeekPokeExpID, PEEK_WORD, Address);
	}
	DWORD   HvPeekDWORD(QWORD Address) {
		return (DWORD)HvxExpansionCall(HvPeekPokeExpID, PEEK_DWORD, Address);
	}
	QWORD   HvPeekQWORD(QWORD Address) {
		return HvxExpansionCall(HvPeekPokeExpID, PEEK_QWORD, Address);
	}

	HRESULT HvPeekBytes(QWORD Address, PVOID Buffer, DWORD Size) {

		// Create a physical buffer to peek into
		VOID* data = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
		ZeroMemory(data, Size);

		HRESULT result = (HRESULT)HvxExpansionCall(HvPeekPokeExpID,
			PEEK_BYTES, Address, (QWORD)MmGetPhysicalAddress(data), Size);

		// If its successful copy it back
		if (result == S_OK) memcpy(Buffer, data, Size);

		// Free our physical data and return our result
		XPhysicalFree(data);
		return result;
	}

	HRESULT HvPokeBYTE(QWORD Address, BYTE Value) {
		return (HRESULT)HvxExpansionCall(HvPeekPokeExpID, POKE_BYTE, Address, Value);
	}
	HRESULT HvPokeWORD(QWORD Address, WORD Value) {
		return (HRESULT)HvxExpansionCall(HvPeekPokeExpID, POKE_WORD, Address, Value);
	}
	HRESULT HvPokeDWORD(QWORD Address, DWORD Value) {
		return (HRESULT)HvxExpansionCall(HvPeekPokeExpID, POKE_DWORD, Address, Value);
	}
	HRESULT HvPokeQWORD(QWORD Address, QWORD Value) {
		return (HRESULT)HvxExpansionCall(HvPeekPokeExpID, POKE_QWORD, Address, Value);
	}
	HRESULT HvPokeBytes(QWORD Address, PVOID Buffer, DWORD Size) {

		// Create a physical buffer to poke from
		VOID* data = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
		memcpy(data, Buffer, Size);

		HRESULT result = (HRESULT)HvxExpansionCall(HvPeekPokeExpID,
			POKE_BYTES, Address, (QWORD)MmGetPhysicalAddress(data), Size);

		// Free our physical data and return our result
		XPhysicalFree(data);
		return result;
	}
}
#pragma warning(pop)