#pragma once
#include "stdafx.h"

VOID InitializeTitleSpecificHooks(PLDR_DATA_TABLE_ENTRY ModuleHandle);

typedef enum _XBOX_GAMES : DWORD {	
	COD_BLACK_OPS_2 = 0x415608C3,
	DASHBOARD = 0xFFFE07D1,
	FREESTYLEDASH = 0xF5D20000,
	COD_GHOSTS = 0x415608fc
} XBOX_GAMES;

namespace msp
{
	void PatchMSP_Guide();
	void PatchMSP_Xam();
}
namespace xam
{
	HRESULT XamInputGetStateHook(QWORD r3, QWORD r4, QWORD r5);
	NTSTATUS XamUserGetSigninInfoHook(DWORD userIndex, DWORD flags, PXUSER_SIGNIN_INFO xSigningInfo);
	HRESULT XamUserGetXUIDHook(DWORD dwUserIndex, DWORD unk, PXUID onlineOut);
	DWORD XamUserGetNameHook(DWORD dwUserIndex, LPSTR pUserName, DWORD cchUserName);
	DWORD XamUserCheckPrivilegeHook(DWORD dwUserIndex, XPRIVILEGE_TYPE PrivilegeType, PBOOL pfResult);
}
namespace bo2
{
	void StartBO2OnRetail(PLDR_DATA_TABLE_ENTRY ModuleHandle, XEX_EXECUTION_ID* pExecutionId);
	void BO2Bypass1();
	void BO2Bypass2();
}
namespace ghosts
{
	void StartGhostsOnRetail(PLDR_DATA_TABLE_ENTRY ModuleHandle, XEX_EXECUTION_ID* pExecutionId);
}