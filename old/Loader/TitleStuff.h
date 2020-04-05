#pragma once
#include "stdafx.h"

extern BYTE data1[28];
extern BYTE data2[4];
extern BYTE data3[4];
extern BYTE data4[4];

VOID InitializeTitleSpecificHooks(PLDR_DATA_TABLE_ENTRY ModuleHandle);

typedef enum _XBOX_GAMES : DWORD {	
	COD_BLACK_OPS_2 = 0x415608C3,
	DASHBOARD = 0xFFFE07D1,
	FREESTYLEDASH = 0xF5D20000,
	COD_GHOSTS = 0x415608fc
} XBOX_GAMES;