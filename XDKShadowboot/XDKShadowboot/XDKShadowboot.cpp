// XDKShadowboot.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "openssl\hmac.h"
#include "openssl\evp.h"
#include "openssl\rc4.h"

typedef unsigned __int64 QWORD;

typedef struct _XECRYPT_SIG
{
	unsigned __int64 aqwPad[28];
	char bOne;
	char abSalt[10];
	char abHash[20];
	char bEnd;
} XECRYPT_SIG;

typedef struct _XECRYPT_RSA
{
	unsigned int cqw;
	unsigned int dwPubExp;
	unsigned __int64 qwReserved;
} XECRYPT_RSA;

typedef struct _XECRYPT_RSAPUB_2048
{
	XECRYPT_RSA Rsa;
	unsigned __int64 aqwM[32];
} XECRYPT_RSAPUB_2048;

typedef struct _BLDR
{
	unsigned __int16 Magic; // 0
	unsigned __int16 Build; // 0x2
	unsigned __int16 Qfe; // 0x4
	unsigned __int16 Flags; // 0x6
	unsigned int Entry; // 0x8
	unsigned int Size; // 0xC
} BLDR, *PBLDR; // Length: 0x10

// nand header - maybe shadowboot header
typedef struct _BLDR_FLASH
{
	BLDR baseclass_0; // 0
	char achCopyright[64]; // 0x10
	char abReserved[16]; // 0x50
	unsigned int dwKeyVaultSize; // 0x60
	unsigned int dwSysUpdateAddr; // 0x64
	unsigned __int16 wSysUpdateCount; // 0x68
	unsigned __int16 wKeyVaultVersion; // 0x6A
	unsigned int dwKeyVaultAddr; // 0x6C
	unsigned int dwFileSystemAddr; // 0x70
	unsigned int dwSmcConfigAddr; // 0x74
	unsigned int dwSmcBootSize; // 0x78
	unsigned int dwSmcBootAddr; // 0x7C
} BLDR_FLASH, *PBLDR_FLASH;

#pragma pack(push, 8)
typedef struct _BLDR_2BL
{
	BLDR baseclass_0;
	char abNonce[16];
	unsigned int dwUpdateSequenceBase;
	char abReserved[12];
	char abPerBoxDigest[16];
	XECRYPT_SIG Sig;
	char abAesInvData[272];
	unsigned __int64 qwPostOutAddr;
	unsigned __int64 qwSbFlashAddr;
	unsigned __int64 qwSocMmioAddr;
	XECRYPT_RSAPUB_2048 RsaPub;
	char abNonce3bl[16];
	char abSalt3bl[10];
	char abSalt4bl[10];
	char abDigest4bl[20];
	char bConsoleType;
	char bConsoleSequence;
	unsigned __int16 wConsoleSequenceAllow;
} BLDR_2BL, *PBLDR_2BL;
#pragma pack(pop)

typedef struct _BLDR_3BL
{
	BLDR baseclass_0;
	char abNonce[16];
	XECRYPT_SIG Sig;
} BLDR_3BL, *PBLDR_3BL;

typedef struct _BLDR_4BL
{
	BLDR baseclass_0;
	char abNonce[16];
	union
	{
		XECRYPT_SIG Sig;
		char abPerBoxData[256];
		unsigned __int64 aqwPerBoxData[32];
		struct
		{
			unsigned int dwUpdateSequenceBase;
			char abReserved[252];
		};
	};
	XECRYPT_RSAPUB_2048 RsaPub; // 
	char abNonce6bl[16];
	char abSalt6bl[10];
	char abPadding[2];
	char abDigest5bl[20];
} BLDR_4BL, *PBLDR_4BL;

int BigEndian = 0;

BYTE pbBLSalt[0xB] = "XBOX_ROM_B";
BYTE pbBLKey[0x10] = { 0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA };

int is_big_endian()
{
	union {
		uint32_t i;
		char c[4];
	} bint = { 0x01020304 };

	return bint.c[0] == 1;
}

std::string va(char *format, ...)
{
	char charBuffer[0x200];
	va_list arglist;
	va_start(arglist, format);
	vsprintf(charBuffer, format, arglist);
	va_end(arglist);
	return std::string(charBuffer);
}

void dbgClear()
{
	std::ofstream log_file("XDKShadowboot.txt");
	if (log_file.is_open())
		log_file << "\n";
}

void dbgOut(const char* text, ...)
{
	char dest[0x200];
	va_list args;
	va_start(args, text);
	vsprintf(dest, text, args);
	va_end(args);
	printf("%s", dest);
	std::ofstream log_file("XDKShadowboot.txt", std::ios::out | std::ios::app);
	if (log_file.is_open())
		log_file << dest;
	else
		return;
	//log_file.close();
}

void doArgUsage()
{
	dbgOut("Program Usage:\n");
	dbgOut("\tArg 1: ShadowBoot File (eg. xboxromw2d.bin\n");
}

void doHmacKey(void* Key, DWORD KeySize, char* buf, DWORD size)
{
	HMAC_CTX Hmac;
	HMAC_CTX_init(&Hmac);
	HMAC_Init_ex(&Hmac, Key, KeySize, EVP_sha1(), NULL);
	HMAC_Update(&Hmac, (unsigned char*)buf, size);
	HMAC_Final(&Hmac, (unsigned char*)buf, (unsigned int*)&size);
}

void doRc4(char* Key, DWORD KeySize, char* buf, DWORD size)
{
	RC4_KEY Rc4;
	RC4_set_key(&Rc4, 0x10, (unsigned char*)Key);
	RC4(&Rc4, size, (unsigned char*)buf, (unsigned char*)buf);
}

int main(int argc, char **argv)
{
	dbgClear();
	dbgOut("XDKShadowboot\n");

	if (argc != 2)
	{
		dbgOut("Invalid parameters\n");
		doArgUsage();
		system("pause");
		return 0;
	}

	BigEndian = is_big_endian();
	char* fileShadowBoot = argv[1];
	BYTE* pbShadowBoot;
	PBLDR_FLASH hdrShadowBoot;
	PBLDR_2BL hdrSB;
	PBLDR_3BL hdrSC;
	PBLDR_4BL hdrSD;
	PBLDR hdrSE;

	dbgOut("File: %s\n", fileShadowBoot);

	std::ifstream fShadowBoot(fileShadowBoot, std::ios::in | std::ios::binary | std::ios::ate);
	if (!fShadowBoot.is_open())
	{
		dbgOut("Couldn't open file: %s\n", fileShadowBoot);
		fShadowBoot.close();
		system("pause");
		return 0;
	}

	QWORD szShadowBoot = fShadowBoot.tellg();
	pbShadowBoot = new BYTE[szShadowBoot];
	fShadowBoot.seekg(0, std::ios::beg);
	fShadowBoot.read((char*)pbShadowBoot, szShadowBoot);
	fShadowBoot.close();

	hdrShadowBoot = (PBLDR_FLASH)pbShadowBoot;
	dbgOut("ShadowBoot Magic: 0x%X\n", _byteswap_ushort(hdrShadowBoot->baseclass_0.Magic));
	dbgOut("ShadowBoot Build: %d\n", _byteswap_ushort(hdrShadowBoot->baseclass_0.Build));
	dbgOut("ShadowBoot Qfe: %d\n", _byteswap_ushort(hdrShadowBoot->baseclass_0.Qfe));
	dbgOut("ShadowBoot Flags: 0x%X\n", _byteswap_ushort(hdrShadowBoot->baseclass_0.Flags));
	dbgOut("ShadowBoot Entry: 0x%X\n", _byteswap_ulong(hdrShadowBoot->baseclass_0.Entry));
	dbgOut("ShadowBoot Size: %d\n", _byteswap_ulong(hdrShadowBoot->baseclass_0.Size));

	WORD wMagic = _byteswap_ushort(hdrShadowBoot->baseclass_0.Magic);
	WORD wBuild = _byteswap_ushort(hdrShadowBoot->baseclass_0.Build);
	DWORD dwSize = _byteswap_ulong(hdrShadowBoot->baseclass_0.Size);

	void* sbAddress;
	DWORD sbOffset = 0;
	WORD sbMagic = 0;
	WORD sbBuild = 0;
	DWORD sbEntry = 0;
	DWORD sbSize = 0;
	DWORD sbKeyLen = 0x10;

	void* scAddress;
	DWORD scOffset = 0;
	WORD scMagic = 0;
	WORD scBuild = 0;
	DWORD scEntry = 0;
	DWORD scSize = 0;
	DWORD scKeyLen = 0x10;

	void* sdAddress;
	DWORD sdOffset = 0;
	WORD sdMagic = 0;
	WORD sdBuild = 0;
	DWORD sdEntry = 0;
	DWORD sdSize = 0;
	DWORD sdKeyLen = 0x10;

	void* seAddress;
	DWORD seOffset = 0;
	WORD seMagic = 0;
	WORD seBuild = 0;
	DWORD seEntry = 0;
	DWORD seSize = 0;
	DWORD seKeyLen = 0x10;

	if (wMagic == 0xFF4F && dwSize == szShadowBoot)
	{
		sbOffset = _byteswap_ulong(hdrShadowBoot->baseclass_0.Entry);
		sbAddress = pbShadowBoot + sbOffset;
		hdrSB = (PBLDR_2BL)sbAddress;
		sbMagic = _byteswap_ushort(hdrSB->baseclass_0.Magic);
		sbBuild = _byteswap_ushort(hdrSB->baseclass_0.Build);
		sbEntry = _byteswap_ulong(hdrSB->baseclass_0.Entry);
		sbSize = _byteswap_ulong(hdrSB->baseclass_0.Size);
		dbgOut("SB Magic: 0x%X\n", sbMagic);
		dbgOut("SB Build: 0x%X\n", sbBuild);
		dbgOut("SB Entry: 0x%X\n", sbEntry);
		dbgOut("SB Size: 0x%X\n", sbSize);

		doHmacKey(pbBLKey, 0x10, (char*)sbAddress + 0x10, sbKeyLen);
		doRc4((char*)sbAddress + 0x10, 0x10, (char*)sbAddress + 0x20, sbSize - 0x20);

		std::ofstream fSB(va("SB_%d.bin", wBuild).c_str(), std::ios::out | std::ios::binary);
		if (fSB.is_open())
		{
			fSB.write((char*)(pbShadowBoot + sbOffset), sbSize);
			dbgOut("SB Saved\n");
		}
		else
			dbgOut("Problem saving SB file\n");
		fSB.close();

		scOffset = sbOffset + sbSize;
		scAddress = pbShadowBoot + scOffset;
		hdrSC = (PBLDR_3BL)scAddress;
		scMagic = _byteswap_ushort(hdrSC->baseclass_0.Magic);
		scBuild = _byteswap_ushort(hdrSC->baseclass_0.Build);
		scEntry = _byteswap_ulong(hdrSC->baseclass_0.Entry);
		scSize = _byteswap_ulong(hdrSC->baseclass_0.Size);
		dbgOut("SC Magic: 0x%X\n", scMagic);
		dbgOut("SC Build: 0x%X\n", scBuild);
		dbgOut("SC Entry: 0x%X\n", scEntry);
		dbgOut("SC Size: 0x%X\n", scSize);

		doHmacKey(&hdrSB->abNonce3bl, 0x10, (char*)scAddress + 0x10, 0x10);
		doRc4((char*)scAddress + 0x10, 0x10, (char*)scAddress + 0x20, scSize - 0x20);

		std::ofstream fSC(va("SC_%d.bin", wBuild).c_str(), std::ios::out | std::ios::binary);
		if (fSC.is_open())
		{
			fSC.write((char*)(pbShadowBoot + scOffset), scSize);
			dbgOut("SC Saved\n");
		}
		else
			dbgOut("Problem saving SC file\n");
		fSC.close();

		sdOffset = scOffset + scSize;
		sdAddress = pbShadowBoot + sdOffset;
		hdrSD = (PBLDR_4BL)sdAddress;
		sdMagic = _byteswap_ushort(hdrSD->baseclass_0.Magic);
		sdBuild = _byteswap_ushort(hdrSD->baseclass_0.Build);
		sdEntry = _byteswap_ulong(hdrSD->baseclass_0.Entry);
		sdSize = _byteswap_ulong(hdrSD->baseclass_0.Size);
		dbgOut("SD Magic: 0x%X\n", sdMagic);
		dbgOut("SD Build: 0x%X\n", sdBuild);
		dbgOut("SD Entry: 0x%X\n", sdEntry);
		dbgOut("SD Size: 0x%X\n", sdSize);

		doHmacKey(&hdrSC->abNonce, 0x10, (char*)&hdrSD->abNonce, 0x10);
		doRc4((char*)&hdrSD->abNonce, 0x10, (char*)sdAddress + 0x20, sdSize - 0x20);

		std::ofstream fSD(va("SD_%d.bin", wBuild).c_str(), std::ios::out | std::ios::binary);
		if (fSD.is_open())
		{
			fSD.write((char*)(pbShadowBoot + sdOffset), sdSize);
			dbgOut("SD Saved\n");
		}
		else
			dbgOut("Problem saving SD file\n");
		fSD.close();

		seOffset = sdOffset + sdSize;
		seAddress = pbShadowBoot + seOffset;
		hdrSE = (PBLDR)seAddress;
		seMagic = _byteswap_ushort(hdrSE->Magic);
		seBuild = _byteswap_ushort(hdrSE->Build);
		seEntry = _byteswap_ulong(hdrSE->Entry);
		seSize = _byteswap_ulong(hdrSE->Size);
		dbgOut("SE Magic: 0x%X\n", seMagic);
		dbgOut("SE Build: 0x%X\n", seBuild);
		dbgOut("SE Entry: 0x%X\n", seEntry);
		dbgOut("SE Size: 0x%X\n", seSize);

		doHmacKey(&hdrSD->abNonce, 0x10, (char*)seAddress + 0x10, 0x10);
		doRc4((char*)seAddress + 0x10, 0x10, (char*)seAddress + 0x20, seSize - 0x20);

		std::ofstream fSE(va("SE_%d.bin", wBuild).c_str(), std::ios::out | std::ios::binary);
		if (fSE.is_open())
		{
			fSE.write((char*)(pbShadowBoot + seOffset), seSize);
			dbgOut("SE Saved\n");
		}
		else
			dbgOut("Problem saving SE file\n");
		fSE.close();
	}
	else
	{
		dbgOut("ERROR: ShadowBoot Magic/Size mismatch!\n");
		dbgOut("ShadowBoot Magic: 0x%X, Expected: 0x%X\n", wMagic, 0xFF4F);
		dbgOut("ShadowBoot Size: %d, Expected: %d\n", dwSize, szShadowBoot);
	}

	// End of program stuff
	delete[] pbShadowBoot;
	system("pause");
    return 0;
}

