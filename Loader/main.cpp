#include "stdafx.h"
#include "TitleStuff.h"
#include "KeyVault.h"
#include "Hooks.h"
#include "Dump.h"
#include "crypto.h"

#define DbgOut(...) DbgOut("")
#define DbgPrint(...) DbgOut(...)
#define DBGBUILD true
//#define SPOOF_MS_POINTS
//#define ADDRESSDUMP

#define DUMP_RESP_FAKE "usb:\\XeKeys\\XeKeysExecute_resp_fake.bin"

#define HvToSRAM(addy) (addy >> 6) & 0xFFFFFFFE
#define SRAMToHv(addy) (addy & 0xFFFFFFFF) << 6

//typedef unsigned long u64;

// current 17511 challenge
BYTE ChallengeHash[0x10] = {
	0x60, 0x1D, 0x32, 0x4B, 0x53, 0xFA, 0x35, 0xFF, 0xB7, 0x26, 0x20, 0x36, 0xC2, 0xC4, 0xF8, 0x3B
};

//typedef DWORD (*XEKEYSEXECUTE)(BYTE* chalData, DWORD size, BYTE* HVSalt, UINT64 krnlBuild, UINT64 r7, UINT64 r8);
//XEKEYSEXECUTE XeKeysExecute = (XEKEYSEXECUTE)resolveFunct("xboxkrnl.exe", 607);
BOOL DecryptChallenge(BYTE* data, DWORD fileSize);

DWORD XeKeysExecuteHook(BYTE* chalData, DWORD size, BYTE* HVSalt, PVOID krnlBuild, PVOID r7, PVOID r8)
{
	// for connecting a debugger to the console while the challenge executes
	/*
	for(int i=0;i<30;i++)
	{
		DbgOut("%d SECONDS TO CONNECT\n", (30 - i));
		Sleep(1000);
	}
	*/

	DbgOut("-------------XeKeysExecute:-------------\n");

	DbgOut("Time: %s\n", getTime().c_str());

	// Decrypt the challenge data
	// Seems to share the same header as a bootloader
	// char[2] Magic
	// short Version
	// int Flags
	// int EntryPoint
	// int Size
	// byte[0x10] HMAC Hash -> RC4 Key
	DWORD dataSize = *(DWORD*)(chalData + 0xC);

	// hashes the challenge, if hashes dont match, challenge has changed
	BYTE chalHash[0x10];
	XECRYPT_SHA_STATE shaC;
	XeCryptShaInit(&shaC);
	XeCryptShaUpdate(&shaC, chalData, dataSize);
	XeCryptShaFinal(&shaC, chalHash, 0x10);
	if(memcmp(&chalHash, &ChallengeHash, 0x10) != 0)
	{
		DbgOut("UNKNOWN CHALLENGE\nDUMPING EVERYTHING AND SHUTTING DOWN\n");
		CWriteFile(va("usb:\\XeKeys\\chalhash_%s.bin", getTime().c_str()).c_str(), &chalHash, 0x10);
		CWriteFile(va("usb:\\XeKeys\\chalhash-stored_%s.bin", getTime().c_str()).c_str(), &ChallengeHash, 0x10);

		if(!DecryptChallenge(chalData, dataSize))
			DbgOut("Error decrypting challenge\n");
		if(!CWriteFile(DUMP_HVSALT, HVSalt, 0x10))
			DbgOut("Error Dumping HV Salt\n");

		BYTE* physSalt = (BYTE*)MmGetPhysicalAddress(HVSalt);
		XeKeysExecute(chalData, size, physSalt, krnlBuild, r7, r8);
		if(!CWriteFile(DUMP_RESP, chalData, size))
			DbgOut("Error Creating Response File\n");

		dump::DumpHv();
		dump::DumpCache();

		DbgOut("FILES DUMPED\nSHUTTING DOWN NOW!\n");
		XNotify("INVALID CHALLENGE\n");
		Sleep(5000);
		HalReturnToFirmware(HalPowerDownRoutine);
		return 1;
	}

	// Execute the challenge
	//			   0000000200016118
#ifdef ADDRESSDUMP
		HvxPokeBytes(0x0000000200016118ULL, MyAddy, 4);
		//HvxPokeBytes(0x000000000000B618ULL, XeCrypt_offsets, 0x30);
		HvxPokeBytes(0x000000000000B618ULL, XeCrypt_data, 0x50);
		//HvxPokeBytes(0x000000000000B618ULL, XeCrypt_r31, 0x20);
		DbgOut("XeCryptPatched\n");
#endif

	std::string strt = va("usb:\\XeKeys\\data1_%s.bin\0", getTime().c_str());
	//DumpData(strt);

	DbgOut("Executing Challenge...\n");

	BYTE* physSalt = (BYTE*)MmGetPhysicalAddress(HVSalt); // Do what we patched
	DbgOut("r3 = 0x%08X, r4 = 0x%08X, r5 = 0x%08X\n", chalData, size, physSalt);
	DbgOut("r5-2 = 0x%016I64X, r6 = 0x%016I64X, r7 = 0x%016I64X, r8 = 0x%016I64X\n", physSalt, krnlBuild, r7, r8);
	XeKeysExecute(chalData, size, physSalt, krnlBuild, r7, r8); // go to actual kernel function

	DbgPrint("Challenge Executed\nAdding our response\n");

	//DumpData(va("usb:\\XeKeys\\data2_%s.bin\0", getTime().c_str()));

	//dump::DumpHv();
	//dump::DumpCache();

	PBYTE pHV = (PBYTE)XPhysicalAlloc(0x40000, MAXULONG_PTR, NULL, PAGE_READWRITE);
	PBYTE pCache = (PBYTE)XPhysicalAlloc(0x10000, MAXULONG_PTR, NULL, PAGE_READWRITE);
	memset(pHV, 0x0, 0x40000);
	memset(pCache, 0, 0x10000);
	if (!CReadFile(PATH_HV, pHV, 0x40000))
	{
		DbgOut("HV Failed To Open!\n");
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
	}
	if (!CReadFile(PATH_CACHE, pCache, 0x10000))
	{
		DbgOut("Cache Failed To Open!\n");
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
	}

	BYTE EccSalt[0x2];
	Hvx::HvPeekBytes(0x800002000001F810LL, EccSalt, 2);

	//memcpy(pHV+0x1F810, cpuKey, 2);

	memcpy(chalData+0x28, pHV, 8);
	memcpy(chalData+0x30, pHV+0x10, 8);
	memcpy(chalData+0x38, pHV+0x30, 4);
	memcpy(chalData+0x3C, pHV+0x74, 4);
	*(QWORD*)(chalData+0x40) = 0x0000000200000000LL;
	*(QWORD*)(chalData+0x48) = 0x0000010000000000LL;

	XECRYPT_SHA_STATE sha;
	XeCryptShaInit(&sha);
	XeCryptShaUpdate(&sha, HVSalt, 0x10);
	XeCryptShaUpdate(&sha, pHV+0x34, 0x40);
	XeCryptShaUpdate(&sha, pHV+0x78, 0xF88);
	XeCryptShaUpdate(&sha, pHV+0x100C0, 0x40);
	XeCryptShaUpdate(&sha, pHV+0x10350, 0xDF0);
	XeCryptShaUpdate(&sha, pHV+0x16D20, 0x2E0);
	XeCryptShaUpdate(&sha, pHV+0x20000, 0xFFC);
	XeCryptShaUpdate(&sha, pHV+0x30000, 0xFFC);
	XeCryptShaFinal(&sha, chalData+0xEC, 0x14);

	// Right offsets and sizes, wrong data
	// 0x50....

	// cpukey
	XeCryptSha(kv::cpuKey, 0x10, 0, 0, 0, 0, chalData+0x64, 0x14);

	char hvData[0x80];
	short respdata = 0x1B5;
	BYTE Flags[2] = { 0x07, 0x60 };
	Hvx::HvPeekBytes(0x0000000200010040ULL, hvData, 0x80);

	memset(chalData+0x100, 0, 0xF00);
	//memcpy(chalData+0x2E, chalData+0x30, 2); //Copy our BLDR Flags from Original Postion @ 0x30, to 0x2E
	//memcpy(chalData+0x30, Flags, 2); //Copy Correct Flags for 0x30 (Static)
	memcpy(chalData+0x70, hvData, 0x80);
	memcpy(chalData+0xF8, &respdata, 2); // dont think anyone knows what exactly theyre checking here... always the same on hacked or retail

	DbgPrint("Response added\nDumping response...\n");

	if(!CWriteFile(DUMP_RESP, chalData, size))
	{
		DbgOut("Error Creating Response File\n");
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
	}

	DbgPrint("Response sent, doing xnotify\n");
	XNotify("Response Sent");
	XPhysicalFree(pHV);
	Sleep(2000);
	//HalReturnToFirmware(HalFatalErrorRebootRoutine);
	return 0;
}

BOOL DecryptChallenge(BYTE* data, DWORD fileSize)
{
	DbgPrint("Decrypting XeKeysExecute Challenge Data\n");
	XECRYPT_RC4_STATE rc4;
	BYTE* decChalData = (BYTE*)XPhysicalAlloc(fileSize, MAXULONG_PTR, 0, PAGE_READWRITE);
	memcpy(decChalData, data, fileSize);
	BYTE* rc4Key = (BYTE*)XPhysicalAlloc(0x10, MAXULONG_PTR, 0, PAGE_READWRITE);
	BYTE key[0x10] = {0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA}; // found in HV
	XeCryptHmacSha((BYTE*)key, 0x10, decChalData + 0x10, 0x10, 0, 0, 0, 0, rc4Key, 0x10);
	XeCryptRc4Key(&rc4, rc4Key, 0x10);
	XeCryptRc4Ecb(&rc4, decChalData + 0x20, fileSize - 0x20);
	HANDLE hFile;
	DWORD size;
	hFile = CreateFile(DUMP_CHALLENGE, GENERIC_WRITE,
		FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if( hFile != INVALID_HANDLE_VALUE)
	{
		DbgPrint("Created Challenge File\n");
		if(WriteFile(hFile, decChalData, fileSize, &size, NULL) )
		{
			CloseHandle(hFile);
			XPhysicalFree(decChalData);
			XPhysicalFree(rc4Key);
			DbgPrint("Decrypted challenge data saved\n");
			return true;
		}
		else
			return false;
	}
	return false;
}

BYTE pbHook0Payload[364] = {
	0x00, 0x00, 0x00, 0x06, 0x00, 0x03, 0x25, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x03, 0xFF, 0xD0,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x7D, 0x88, 0x02, 0xA6, 0xF9, 0x81, 0xFF, 0xF8, 0xFB, 0xE1, 0xFF, 0xF0, 0xFB, 0xC1, 0xFF, 0xE8,
	0xFB, 0xA1, 0xFF, 0xE0, 0xFB, 0x81, 0xFF, 0xD8, 0xFB, 0x61, 0xFF, 0xD0, 0xFB, 0x41, 0xFF, 0xC8,
	0xFB, 0x21, 0xFF, 0xC0, 0xFB, 0x01, 0xFF, 0xB8, 0xFA, 0xE1, 0xFF, 0xB0, 0xFA, 0xC1, 0xFF, 0xA8,
	0xF8, 0x21, 0xFF, 0x11, 0x3B, 0xE0, 0x00, 0x00, 0x63, 0xFF, 0xB6, 0x20, 0xEB, 0xBF, 0x00, 0x08,
	0xEB, 0xFF, 0x00, 0x00, 0xEB, 0xDF, 0x00, 0x00, 0x7C, 0x3E, 0xE8, 0x40, 0x40, 0x80, 0x00, 0x0C,
	0x28, 0x3E, 0x00, 0x00, 0x40, 0x82, 0x00, 0x08, 0x7F, 0xFE, 0xFB, 0x78, 0xF8, 0x7E, 0x00, 0x09,
	0xF8, 0x9E, 0x00, 0x09, 0xF8, 0xBE, 0x00, 0x09, 0xF8, 0xDE, 0x00, 0x09, 0xF8, 0xFE, 0x00, 0x09,
	0xFB, 0xDF, 0x00, 0x00, 0x3B, 0xA0, 0x02, 0x00, 0x67, 0xBD, 0x80, 0x00, 0x7B, 0xBD, 0x07, 0xC6,
	0x67, 0xBD, 0x00, 0x02, 0x63, 0xBC, 0x08, 0x00, 0x63, 0xBB, 0x0A, 0x00, 0x63, 0xBA, 0x0C, 0x00,
	0x63, 0xBD, 0x06, 0x00, 0x28, 0x04, 0x00, 0x05, 0x40, 0x82, 0x00, 0x24, 0x7C, 0x3D, 0x28, 0x40,
	0x41, 0x82, 0x00, 0x34, 0x7C, 0x3C, 0x28, 0x40, 0x41, 0x82, 0x00, 0x2C, 0x7C, 0x3B, 0x28, 0x40,
	0x41, 0x82, 0x00, 0x3C, 0x7C, 0x3A, 0x28, 0x40, 0x41, 0x82, 0x00, 0x34, 0x3B, 0xE0, 0x00, 0x00,
	0x63, 0xFF, 0xB6, 0x20, 0xEB, 0xFF, 0x00, 0x20, 0x7F, 0xE9, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x21,
	0x48, 0x00, 0x00, 0x34, 0x38, 0x60, 0x00, 0x00, 0x60, 0x63, 0xB6, 0x20, 0xE8, 0x63, 0x00, 0x10,
	0xF8, 0x66, 0x00, 0x00, 0x7C, 0xC3, 0x33, 0x78, 0x48, 0x00, 0x00, 0x1C, 0x38, 0x60, 0x00, 0x00,
	0x60, 0x63, 0xB6, 0x20, 0xE8, 0x63, 0x00, 0x18, 0xF8, 0x66, 0x00, 0x00, 0x7C, 0xC3, 0x33, 0x78,
	0x48, 0x00, 0x00, 0x04, 0x38, 0x21, 0x00, 0xF0, 0xE9, 0x81, 0xFF, 0xF8, 0xEA, 0xC1, 0xFF, 0xA8,
	0xEA, 0xE1, 0xFF, 0xB0, 0xEB, 0x01, 0xFF, 0xB8, 0xEB, 0x21, 0xFF, 0xC0, 0xEB, 0x41, 0xFF, 0xC8,
	0xEB, 0x61, 0xFF, 0xD0, 0xEB, 0x81, 0xFF, 0xD8, 0xEB, 0xA1, 0xFF, 0xE0, 0xEB, 0xC1, 0xFF, 0xE8,
	0xEB, 0xE1, 0xFF, 0xF0, 0x7D, 0x88, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20
};

BYTE pbHook71Payload[348] = {
	0x00, 0x00, 0x00, 0x06, 0x00, 0x03, 0x25, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x03, 0xFF, 0xD0,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x7D, 0x88, 0x02, 0xA6, 0xF9, 0x81, 0xFF, 0xF8, 0xFB, 0xE1, 0xFF, 0xF0, 0xFB, 0xC1, 0xFF, 0xE8,
	0xFB, 0xA1, 0xFF, 0xE0, 0xFB, 0x81, 0xFF, 0xD8, 0xFB, 0x61, 0xFF, 0xD0, 0xFB, 0x41, 0xFF, 0xC8,
	0xFB, 0x21, 0xFF, 0xC0, 0xFB, 0x01, 0xFF, 0xB8, 0xFA, 0xE1, 0xFF, 0xB0, 0xFA, 0xC1, 0xFF, 0xA8,
	0xF8, 0x21, 0xFF, 0x11, 0x3B, 0xE0, 0x00, 0x00, 0x63, 0xFF, 0xB8, 0x00, 0xEB, 0xBF, 0x00, 0x08,
	0xEB, 0xFF, 0x00, 0x00, 0xEB, 0xDF, 0x00, 0x00, 0x7C, 0x3E, 0xE8, 0x40, 0x40, 0x80, 0x00, 0x0C,
	0x28, 0x3E, 0x00, 0x00, 0x40, 0x82, 0x00, 0x08, 0x7F, 0xFE, 0xFB, 0x78, 0xF8, 0x7E, 0x00, 0x09,
	0xF8, 0x9E, 0x00, 0x09, 0xF8, 0xBE, 0x00, 0x09, 0xF8, 0xDE, 0x00, 0x09, 0xF8, 0xFE, 0x00, 0x09,
	0xFB, 0xDF, 0x00, 0x00, 0x3B, 0xA0, 0x02, 0x00, 0x67, 0xBD, 0x80, 0x00, 0x7B, 0xBD, 0x07, 0xC6,
	0x67, 0xBD, 0x00, 0x02, 0x63, 0xBC, 0x08, 0x00, 0x63, 0xBB, 0x0A, 0x00, 0x63, 0xBA, 0x0C, 0x00,
	0x63, 0xBD, 0x06, 0x00, 0x28, 0x04, 0x00, 0x05, 0x40, 0x82, 0x00, 0x24, 0x7C, 0x3D, 0x28, 0x40,
	0x41, 0x82, 0x00, 0x34, 0x7C, 0x3C, 0x28, 0x40, 0x41, 0x82, 0x00, 0x2C, 0x7C, 0x3B, 0x28, 0x40,
	0x41, 0x82, 0x00, 0x34, 0x7C, 0x3A, 0x28, 0x40, 0x41, 0x82, 0x00, 0x2C, 0x3B, 0xE0, 0x00, 0x00,
	0x63, 0xFF, 0xB8, 0x00, 0xEB, 0xFF, 0x00, 0x20, 0x7F, 0xE9, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x21,
	0x48, 0x00, 0x00, 0x24, 0x38, 0x60, 0x00, 0x00, 0x60, 0x63, 0xB8, 0x00, 0xE8, 0x63, 0x00, 0x10,
	0x48, 0x00, 0x00, 0x14, 0x38, 0x60, 0x00, 0x00, 0x60, 0x63, 0xB8, 0x00, 0xE8, 0x63, 0x00, 0x18,
	0x48, 0x00, 0x00, 0x04, 0x38, 0x21, 0x00, 0xF0, 0xE9, 0x81, 0xFF, 0xF8, 0xEA, 0xC1, 0xFF, 0xA8,
	0xEA, 0xE1, 0xFF, 0xB0, 0xEB, 0x01, 0xFF, 0xB8, 0xEB, 0x21, 0xFF, 0xC0, 0xEB, 0x41, 0xFF, 0xC8,
	0xEB, 0x61, 0xFF, 0xD0, 0xEB, 0x81, 0xFF, 0xD8, 0xEB, 0xA1, 0xFF, 0xE0, 0xEB, 0xC1, 0xFF, 0xE8,
	0xEB, 0xE1, 0xFF, 0xF0, 0x7D, 0x88, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20
};

BYTE pbBlowFuses[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x7D, 0x88, 0x02, 0xA6, 0xF9, 0x81, 0xFF, 0xF8, 0xFB, 0xE1, 0xFF, 0xF0, 0xFB, 0xC1, 0xFF, 0xE8,
	0xFB, 0xA1, 0xFF, 0xE0, 0xFB, 0x81, 0xFF, 0xD8, 0xFB, 0x61, 0xFF, 0xD0, 0xFB, 0x41, 0xFF, 0xC8,
	0xFB, 0x21, 0xFF, 0xC0, 0xFB, 0x01, 0xFF, 0xB8, 0xFA, 0xE1, 0xFF, 0xB0, 0xFA, 0xC1, 0xFF, 0xA8,
	0xF8, 0x21, 0xFF, 0x11, 0x38, 0x80, 0x00, 0x00, 0x60, 0x84, 0xB6, 0x20, 0xEB, 0xC4, 0x00, 0x00,
	0x78, 0x63, 0xC7, 0x22, 0x7C, 0x7C, 0x1B, 0x78, 0x28, 0x23, 0x00, 0x00, 0x41, 0x82, 0x00, 0x60,
	0x28, 0x23, 0x00, 0x01, 0x41, 0x82, 0x00, 0x60, 0x28, 0x23, 0x00, 0x02, 0x41, 0x82, 0x00, 0x60,
	0x28, 0x23, 0x00, 0x03, 0x41, 0x82, 0x00, 0x60, 0x28, 0x23, 0x00, 0x04, 0x41, 0x82, 0x00, 0x60,
	0x28, 0x23, 0x00, 0x05, 0x41, 0x82, 0x00, 0x60, 0x28, 0x23, 0x00, 0x06, 0x41, 0x82, 0x00, 0x60,
	0x28, 0x23, 0x00, 0x07, 0x41, 0x82, 0x00, 0x60, 0x28, 0x23, 0x00, 0x08, 0x41, 0x82, 0x00, 0x60,
	0x28, 0x23, 0x00, 0x09, 0x41, 0x82, 0x00, 0x60, 0x28, 0x23, 0x00, 0x0A, 0x41, 0x82, 0x00, 0x60,
	0x28, 0x23, 0x00, 0x0B, 0x41, 0x82, 0x00, 0x60, 0x48, 0x00, 0x00, 0x90, 0x3B, 0xE0, 0x00, 0x3F,
	0x48, 0x00, 0x00, 0x58, 0x3B, 0xE0, 0x00, 0x7F, 0x48, 0x00, 0x00, 0x50, 0x3B, 0xE0, 0x00, 0xBF,
	0x48, 0x00, 0x00, 0x48, 0x3B, 0xE0, 0x00, 0xFF, 0x48, 0x00, 0x00, 0x40, 0x3B, 0xE0, 0x01, 0x3F,
	0x48, 0x00, 0x00, 0x38, 0x3B, 0xE0, 0x01, 0x7F, 0x48, 0x00, 0x00, 0x30, 0x3B, 0xE0, 0x01, 0xBF,
	0x48, 0x00, 0x00, 0x28, 0x3B, 0xE0, 0x01, 0xFF, 0x48, 0x00, 0x00, 0x20, 0x3B, 0xE0, 0x02, 0x3F,
	0x48, 0x00, 0x00, 0x18, 0x3B, 0xE0, 0x02, 0x7F, 0x48, 0x00, 0x00, 0x10, 0x3B, 0xE0, 0x02, 0xBF,
	0x48, 0x00, 0x00, 0x08, 0x3B, 0xE0, 0x02, 0xFF, 0x3B, 0xA0, 0x00, 0x40, 0x7B, 0xC4, 0x07, 0xE0,
	0x28, 0x24, 0x00, 0x00, 0x41, 0x82, 0x00, 0x10, 0x38, 0x80, 0x00, 0x00, 0x7F, 0xE3, 0xFB, 0x78,
	0x48, 0x00, 0x95, 0x5B, 0x3B, 0xFF, 0xFF, 0xFF, 0x3B, 0xBD, 0xFF, 0xFF, 0x7B, 0xDE, 0xF8, 0x42,
	0x28, 0x1D, 0x00, 0x00, 0x40, 0x82, 0xFF, 0xD8, 0x7F, 0x83, 0xE3, 0x78, 0x38, 0x21, 0x00, 0xF0,
	0xE9, 0x81, 0xFF, 0xF8, 0xEA, 0xC1, 0xFF, 0xA8, 0xEA, 0xE1, 0xFF, 0xB0, 0xEB, 0x01, 0xFF, 0xB8,
	0xEB, 0x21, 0xFF, 0xC0, 0xEB, 0x41, 0xFF, 0xC8, 0xEB, 0x61, 0xFF, 0xD0, 0xEB, 0x81, 0xFF, 0xD8,
	0xEB, 0xA1, 0xFF, 0xE0, 0xEB, 0xC1, 0xFF, 0xE8, 0xEB, 0xE1, 0xFF, 0xF0, 0x7D, 0x88, 0x03, 0xA6,
	0x7C, 0x7F, 0x1B, 0x78, 0x48, 0x00, 0xA7, 0x8A
};

BYTE pbHook0Buffer[0x10000] = { 0 };
BYTE pbHook71Buffer[0x10000] = { 0 };
BYTE pbHookCPUKey[0x10] = { 0xF2, 0x62, 0xB1, 0xCC, 0xBC, 0x44, 0xE3, 0xC5, 0xB6, 0x18, 0x93, 0xD0, 0x89, 0xAF, 0xA2, 0x69 };

void HookSyscall0()
{
	printf("HookSyscall0\n");

	Hvx::HvPokeBytes(0x20, pbHookCPUKey, 0x10);	

	// Setup our hook settings...
	QWORD pqwExpHookSettings[6];
	pqwExpHookSettings[0] = 0x8000000000000000ULL + (DWORD)MmGetPhysicalAddress(pbHook0Buffer); // dump buffer
	pqwExpHookSettings[1] = pqwExpHookSettings[0] + 0xFFD0; // dump buffer max (with room for error)
	pqwExpHookSettings[2] = (*(QWORD*)pbHookCPUKey); // CPUKey High
	pqwExpHookSettings[3] = (*(QWORD*)(pbHookCPUKey + 8)); // CPUKey Low
	pqwExpHookSettings[4] = 0xB54C; // where we need to jump to after dumping
	pqwExpHookSettings[5] = 0;
	memcpy(pbHook0Payload, pqwExpHookSettings, 0x30); // Copy to the place holders

	// Install the hook
	DWORD dwHookDest = 0xB620;
	DWORD dwHookEntry = dwHookDest + 0x30;
	printf("Installing Hook...\ndwHookDest: %08X\ndwHookEntry: %08\n", dwHookDest, dwHookEntry);
	Hvx::HvPokeBytes(dwHookDest, pbHook0Payload, 364);

	// Hook the syscall table
	BYTE bSyscallID = 0;
	QWORD pqwSyscallTbl = 0x200015E60;
	QWORD pqwExpCallSyscallTblEntry = pqwSyscallTbl + (bSyscallID << 2);
	printf("Hooking Syscall Table...\npqwSyscallTbl: %016llX\npqwExpCallSyscallTblEntry: %016llX\n", pqwSyscallTbl, pqwExpCallSyscallTblEntry);
	Hvx::HvPokeDWORD(pqwExpCallSyscallTblEntry, dwHookEntry);

	printf("Done!\n");
}

void HookSyscall71()
{
	printf("HookSyscall71\n");

	Hvx::HvPokeBytes(0x20, pbHookCPUKey, 0x10);

	// Setup our hook settings...
	QWORD pqwExpHookSettings[6];
	pqwExpHookSettings[0] = 0x8000000000000000ULL + (DWORD)MmGetPhysicalAddress(pbHook71Buffer); // dump buffer
	pqwExpHookSettings[1] = pqwExpHookSettings[0] + 0xFFD0; // dump buffer max (with room for error)
	pqwExpHookSettings[2] = (*(QWORD*)pbHookCPUKey); // CPUKey High
	pqwExpHookSettings[3] = (*(QWORD*)(pbHookCPUKey + 8)); // CPUKey Low
	pqwExpHookSettings[4] = 0xB240; // where we need to jump to after dumping
	pqwExpHookSettings[5] = 0;
	memcpy(pbHook71Payload, pqwExpHookSettings, 0x30); // Copy to the place holders

	// Install the hook
	DWORD dwHookDest = 0xB800;
	DWORD dwHookEntry = dwHookDest + 0x30;
	printf("Installing Hook...\ndwHookDest: %08X\ndwHookEntry: %08\n", dwHookDest, dwHookEntry);
	Hvx::HvPokeBytes(dwHookDest, pbHook71Payload, 348);

	// Hook the syscall table
	BYTE bSyscallID = 0x71;
	QWORD pqwSyscallTbl = 0x200015E60;
	QWORD pqwExpCallSyscallTblEntry = pqwSyscallTbl + (bSyscallID << 2);
	printf("Hooking Syscall Table...\npqwSyscallTbl: %016llX\npqwExpCallSyscallTblEntry: %016llX\n", pqwSyscallTbl, pqwExpCallSyscallTblEntry);
	Hvx::HvPokeDWORD(pqwExpCallSyscallTblEntry, dwHookEntry);

	printf("Done!\n");
}

void HookHvxBlowFuses()
{
	// Setup our hook settings...
	QWORD pqwExpHookSettings[4];
	pqwExpHookSettings[0] = 0xFFFFFFFFFFFFFFFF; // fuse - this is what will be 'flashed' to the fuseline, if you want to blow them all, make it 0xFF repeated
	pqwExpHookSettings[1] = 0; // unused
	pqwExpHookSettings[2] = 0; // unused
	pqwExpHookSettings[3] = 0; // unused
	memcpy(pbBlowFuses, pqwExpHookSettings, 0x20); // Copy to the placeholders

	// Install the hook
	DWORD dwHookDest = 0xB620;
	DWORD dwHookEntry = dwHookDest + 0x20;
	printf("Installing Hook...\n");
	printf("dwHookDest: %08X\n", dwHookDest);
	printf("dwHookEntry: %08X\n", dwHookEntry);
	Hvx::HvPokeBytes(dwHookDest, pbBlowFuses, 408);

	// Hook the syscall
	DWORD dwBranchOP = dwHookEntry | 0x48000002;
	QWORD qwHookLoc = 0xA71C; // the argument we catch - might change on furture dashboards
	Hvx::HvPokeDWORD(qwHookLoc, 0x7F83E378); // mr r3, r28 - give us the argument we sent
	Hvx::HvPokeDWORD(qwHookLoc + 4, dwBranchOP); // bla

	// fix xebuild patches
	Hvx::HvPokeDWORD(0xA560, 0x7D8802A6);
	Hvx::HvPokeDWORD(0xA564, 0x48000299);

	printf("Done!\n");
}

// HvxBlowFuses is part of a irql/dpc system and requires it to be used on thread 0
// all other threads must be put to sleep before changing cpu power settings
// the irql/dpc system is managed by the kernel
// just going through the kernel is much easier than reverse engineering how their irql/dpc system works

// If you just call HvxBlowFuses from the syscall, the console will freeze if its not on thread 0
// or if it is, it will go into a loop and wait for the other threads to sleep before continuing
// which will never happen without the kernel invoking it so it'll just hang
typedef DWORD(*KEBLOWFUSES)(DWORD arg);
KEBLOWFUSES KeBlowFuses = (KEBLOWFUSES)resolveFunct("xboxkrnl.exe", 80);
void BlowTheFuses()
{
	Sleep(5000);
	HookHvxBlowFuses();

	// when calling KeBlowFuses:
	// make sure the bottom byte is 0x10, this is the flag that causes HvxBlowFuses to jump to our code
	// make the top byte the fuseline (0 - 11)
	// make sure nothing else is set in the argument
	// so if i wanted to burn line 0, i'd send 0x010 or 0x10
	// if i wanted to burn line 2, i'd send 0x210
	// ect...

	DWORD ret = KeBlowFuses(0x010ul);
	Sleep(1750);
	if (ret == 0)
		ret = KeBlowFuses(0x310);
	Sleep(1750);
	if (ret == 3)
		ret = KeBlowFuses(0x410);
	Sleep(1750);
	if (ret == 4)
		ret = KeBlowFuses(0x510);
	Sleep(1750);
	if (ret == 5)
		ret = KeBlowFuses(0x610);
	Sleep(1750);
	if (ret != 6)
		XNotify(va("ERROR: %08X, Please Contact Teir", ret));
	else
		XNotify("Loader Loaded");
	Sleep(1750);
	//HalReturnToFirmware(HalRebootQuiesceRoutine);
	return;
}

void Quiesce()
{
	Hvx::HvQuiesceProcessor(1);
}

void BlowFuses()
{
	HANDLE	hThread5;
	DWORD hThreadId5;
	ExCreateThread(&hThread5, 0, &hThreadId5, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)Quiesce, NULL, CREATE_SUSPENDED);
	HANDLE	hThread4;
	DWORD hThreadId4;
	ExCreateThread(&hThread4, 0, &hThreadId4, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)Quiesce, NULL, CREATE_SUSPENDED);
	HANDLE	hThread3;
	DWORD hThreadId3;
	ExCreateThread(&hThread3, 0, &hThreadId3, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)Quiesce, NULL, CREATE_SUSPENDED);
	HANDLE	hThread2;
	DWORD hThreadId2;
	ExCreateThread(&hThread2, 0, &hThreadId2, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)Quiesce, NULL, CREATE_SUSPENDED);
	HANDLE	hThread1;
	DWORD hThreadId1;
	ExCreateThread(&hThread1, 0, &hThreadId1, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)Quiesce, NULL, CREATE_SUSPENDED);
	XSetThreadProcessor(hThread5, 5);
	XSetThreadProcessor(hThread4, 4);
	XSetThreadProcessor(hThread3, 3);
	XSetThreadProcessor(hThread2, 2);
	XSetThreadProcessor(hThread1, 1);
	ResumeThread(hThread5);
	ResumeThread(hThread4);
	ResumeThread(hThread3);
	ResumeThread(hThread2);
	ResumeThread(hThread1);

	Hvx::HvBlowFuses(0x010);

	XNotify("Kv Set");
}

void start()
{
	Sleep(3000);
	DbgOut("[Loader]: Start function entered\n");
	BlowTheFuses();

	//HookSyscall0();
	//HookSyscall71();

	if (Settings::skipTitles)
	{
		DbgOut("Skip titles enabled, we won't hook any titles this time\n");
		Settings::skipBO2 = true;
		Settings::skipGhosts = true;
		Settings::hookTitles = false;
	}

	if (Settings::hookTitles)
	{
		DbgOut("Setting up title hooks...\n");
		if (hookImpStub(MODULE_XAM, MODULE_KERNEL, 409, (DWORD)XexLoadImageHook))
			DbgOut("XexLoadImage Import NOT HOOKED\n");
		if (hookImpStub(MODULE_XAM, MODULE_KERNEL, 408, (DWORD)XexLoadExecutableHook))
			DbgOut("XexLoadExecutable Import NOT HOOKED\n");
		if (hookImpStub(MODULE_XAM, MODULE_KERNEL, 416, (DWORD)XexStartExecutableHook))
			DbgOut("XexStartExecutable NOT HOOKED\n");
	}

	if (Settings::hookXeKeys)
	{
		DbgOut("Setting up XeKeysExecute hook...\n");
		UINT32* addr = (UINT32*)(0x816799E4); // 17511
		addr[0] = 0x60000000;
		patchInJump((PDWORD)(0x81A710EC), (DWORD)XeKeysExecuteHook, false);//xekeys def 17511
		patchInJump((PDWORD)(resolveFunct("xam.xex", 0x195)), (DWORD)XexGetModuleHandleHook, false);
		//if(!hookImpStub("xam.xex", "xboxkrnl.exe", 607, (DWORD)XeKeysExecuteHook))
			//HalReturnToFirmware(6);
	}
	else DbgOut("[Loader] WARNING: XeKeys Hooks Disabled!\n");

	//if (hookImpStub(MODULE_XAM, MODULE_KERNEL, 405, (DWORD)XexGetModuleHandleHook))
		//DbgOut("XexStartExecutable NOT HOOKED\n");

	if (kv::ProcessCpuKey())
		DbgOut("ProcessCpuKey FAILED!\n");

	if (Settings::patchKV)
	{
		if (fileExists(PATH_KV))
		{
			DbgOut("KV found on Hdd, Attempting to apply...\n");
			if (kv::SetKeyVault(PATH_KV))
				DbgOut("SetKeyVault FAILED!\n");
		}

		if (kv::SetMacAddress())
			DbgOut("SetMacAddress FAILED!\n");
	}

	if (Settings::spoofMSP)
		msp::PatchMSP_Xam();

}

int main()
{
	return 474;
}

BOOL APIENTRY DllMain(HANDLE hInstDLL, DWORD reason, LPVOID lpReserved){
	Hvx::InitializeHvPeekPoke();
	HookHvxBlowFuses();
	HANDLE	hThread;
	DWORD hThreadId;
	ExCreateThread(&hThread, 0, &hThreadId, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)BlowFuses, NULL, CREATE_SUSPENDED);
	XSetThreadProcessor(hThread, 0); ResumeThread(hThread);
	switch(reason)
	{
	case DLL_PROCESS_ATTACH:
		printf("[Loader]: Attached\n");
		MountPath("hdd:", "\\Device\\Harddisk0\\Partition1\\", false);
		MountPath("usb:", "\\Device\\Mass0\\", false);
		DbgOut("Loader Started\n");
		start();
		DbgOut("Setup Done\n");
		break;
	case DLL_THREAD_ATTACH:
		printf("[Loader]: Thread Attached\n");
		break;
	case DLL_THREAD_DETACH:
		printf("[Loader]: Thread Detached\n");
		break;
	case DLL_PROCESS_DETACH:
		printf("[Loader]: Detached\n");
		break;
	}
	return TRUE;
}