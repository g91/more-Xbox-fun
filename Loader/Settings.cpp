#include "stdafx.h"
#include "Settings.h"

namespace Settings
{
	bool dbg				= true;
	bool hookTitles			= false;
	bool hookXeKeys			= true;
	bool hookUserInfo		= false;
	bool hookUserGetInfo	= false;
	bool spoofMSP			= true;
	bool patchKV			= true;
	bool skipTitles			= false;

	bool skipBO2			= false;
	bool bypassBO2			= true;
	bool skipGhosts			= false;
	bool bypassGhosts		= false;

	XUID UserXUID			= 0x000900000A8F5239;
	char* UserName			= "Teir";
}

namespace Keys
{
	BYTE BLKey[0x10] = { 0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA };

	BYTE blSlimRSA[0x110] = {
		0x00, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xE9, 0x8D, 0xB5, 0xDC, 0xAF, 0x38, 0x8E, 0xF1, 0x38, 0x9E, 0x28, 0xCB, 0x4A, 0x11, 0xC8, 0x22,
		0x52, 0xE1, 0x1F, 0x53, 0x45, 0x56, 0x60, 0xA2, 0x52, 0xD4, 0xD1, 0x68, 0x4E, 0xCC, 0x80, 0x99,
		0xD7, 0x5C, 0x40, 0xC5, 0xAF, 0x73, 0x0C, 0xCF, 0x44, 0x06, 0xB0, 0x6D, 0x16, 0x91, 0x08, 0x38,
		0xB3, 0x00, 0x2D, 0xBC, 0xEB, 0x1D, 0x0C, 0x1D, 0xC5, 0xC6, 0x68, 0x0B, 0x80, 0x4C, 0x62, 0x0B,
		0x7E, 0xE8, 0x72, 0x0C, 0xCF, 0x1D, 0xB4, 0xBD, 0xEE, 0x4B, 0x11, 0x36, 0xD1, 0xC9, 0x92, 0x1F,
		0xE9, 0xAE, 0xC0, 0x51, 0x52, 0x51, 0xF7, 0x23, 0xD6, 0xBC, 0xF4, 0xE9, 0x58, 0x87, 0x40, 0xB1,
		0x02, 0x66, 0x5A, 0x43, 0xEB, 0x67, 0x5F, 0x50, 0x94, 0x32, 0x34, 0x7A, 0xA7, 0x50, 0xD9, 0xB4,
		0x14, 0x4E, 0xB0, 0x02, 0x31, 0x8B, 0xA7, 0x00, 0x9A, 0x12, 0xC8, 0x3B, 0x8F, 0x76, 0xE4, 0x8F,
		0x33, 0xB5, 0xCD, 0x0C, 0x24, 0x6D, 0x2A, 0xE5, 0x57, 0xA0, 0x44, 0x76, 0x78, 0x41, 0xF4, 0x8F,
		0xCB, 0x3A, 0xB5, 0x0E, 0xA1, 0xA2, 0x56, 0x6D, 0x17, 0xDB, 0x32, 0xCC, 0xB8, 0x5A, 0x5F, 0xAE,
		0xED, 0x9A, 0x62, 0x31, 0x5D, 0x88, 0x7F, 0x6D, 0x9A, 0x53, 0x80, 0xB0, 0x34, 0xC7, 0x42, 0x51,
		0x2D, 0x94, 0x4D, 0x86, 0x09, 0x32, 0x8F, 0x71, 0xA7, 0xBA, 0x16, 0x6C, 0xE6, 0xDC, 0x6B, 0x64,
		0x61, 0x7D, 0x16, 0xB5, 0x20, 0x51, 0xD0, 0xB1, 0x1F, 0xFE, 0x1E, 0x35, 0x56, 0x9A, 0x76, 0x4D,
		0x62, 0x7F, 0x5D, 0xF4, 0xB8, 0x7D, 0xC4, 0x18, 0x2C, 0x81, 0xB7, 0xAF, 0xE4, 0x7D, 0x13, 0x5D,
		0xF4, 0x0F, 0x63, 0x05, 0x3F, 0x1A, 0xED, 0xED, 0x4B, 0xEE, 0xFD, 0x6D, 0x74, 0xE6, 0xA5, 0x92,
		0xA7, 0x99, 0x81, 0x73, 0x95, 0xD8, 0xC7, 0xA5, 0xA1, 0xC7, 0x7B, 0x09, 0x05, 0x85, 0x41, 0x04
	};
}