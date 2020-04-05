#pragma once
#include "stdafx.h"

#define DUMP_USB
#ifdef DUMP_USB
#define DUMP_HVSALT "usb:\\XeKeys\\XeKeysExecute_HVSalt.bin"
#define DUMP_CHALLENGE "usb:\\XeKeys\\XeKeysExecute_chalData_dec.bin"
#define DUMP_RESP "usb:\\XeKeys\\XeKeysExecute_resp.bin"
#else
#define DUMP_HVSALT "Hdd:\\XeKeys\\XeKeysExecute_HVSalt.bin"
#define DUMP_CHALLENGE "Hdd:\\XeKeys\\XeKeysExecute_chalData_dec.bin"
#define DUMP_RESP "Hdd:\\XeKeys\\XeKeysExecute_resp.bin"
#endif

#define PATH_KV "Hdd:\\KV.bin"
#define PATH_CPU "Hdd:\\cpukey.bin"
#define PATH_HV "Hdd:\\XeKeys\\HV_17511.bin"
#define PATH_CACHE "Hdd:\\XeKeys\\Cache_17511.bin"

#define SPACE_NAND 0x80000200C8000000ULL
#define SPACE_1BL 0x8000020000000000ULL
#define SPACE_SRAM 0x8000020000010000ULL
#define SPACE_FUSES 0x8000020000020000ULL
#define SPACE_FUSE_DEVICE 0x8000020000022000ULL
#define SPACE_SECURITY_ENGINE 0x8000020000024000ULL
#define SPACE_RNG 0x8000020000026000ULL
#define SPACE_CBB_RELOC 0x30036C0ULL

namespace Settings
{
	extern bool dbg;					// debug build
	extern bool hookTitles;				// hook titles when loaded
	extern bool hookXeKeys;				// hook the challenge
	extern bool hookUserInfo;			// hook user info for spoofing
	extern bool hookUserGetInfo;		// hook get user info for spoofing
	extern bool spoofMSP;				// spoof MS Points
	extern bool patchKV;				// use kv from storage
	extern bool skipTitles;				// skip all title patches

	extern bool skipBO2;				// don't do anything to bo2
	extern bool bypassBO2;				// bypass bo2 (ignored if skipped)
	extern bool skipGhosts;				// don't do anything to ghosts
	extern bool bypassGhosts;			// bypass ghosts (ignored if skipped)

	extern XUID UserXUID;				// xuid to spoof
	extern char* UserName;				// gamertag to spoof
}

namespace Keys
{
	extern BYTE BLKey[0x10];			// 1BL Key
	extern BYTE blSlimRSA[0x110];		// public bootloader rsa key
}