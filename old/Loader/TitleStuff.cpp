#include "stdafx.h"
#include "TitleStuff.h"
#include "Hooks.h"

XUID spoofedXUID = 0x000984444444449F;
int NOP = 0x60000000;
short alwaysBranchPatch = 0x4800;
static bool isFrozen = false;
#define SPOOF_MS_POINTS

extern BYTE data1[28] = { 0x38, 0x80, 0x00, 0x05, 0x80, 0x63, 0x00, 0x1C, 0x90, 0x83, 0x00, 0x04, 0x38, 0x80, 0x27, 0x0F, 0x90, 0x83, 0x00, 0x08, 0x38, 0x60, 0x00, 0x00, 0x4E, 0x80, 0x00, 0x20 };
extern BYTE data2[4] = { 0x60, 0x00, 0x00, 0x00 };
extern BYTE data3[4] = { 0x48, 0x00, 0x00, 0xC8 };
extern BYTE data4[4] = { 0x39, 0x60, 0x00, 0x00 };

BYTE tstData[24] = { 0x7D, 0x88, 0x02, 0xA6, 0x91, 0x81, 0xFF, 0xF8, 0x94, 0x21, 0xFF, 0xA0, 0x38, 0xC1, 0x00, 0x50, 0x38, 0xA0, 0x00, 0x00, 0x38, 0x80, 0x00, 0x09 };

VOID BlackOps2()
{
	*(QWORD*)0x823C07C8 = 0x6000000038600000; //Demonware Be Gone
	BYTE Data[] = { 0x60, 0x00, 0x00, 0x00 };
	memcpy((BYTE*)0x8259A65C, Data, 4); // Disable challenge log check
	memcpy((BYTE*)0x82497EB0, Data, 4); // Disable call to protections
	memcpy((BYTE*)0x82497F30, Data, 4); // Cheat
	memcpy((BYTE*)0x82497EE0, Data, 4); // Write
	memcpy((BYTE*)0x82497EC8, Data, 4); // Read
	memcpy((BYTE*)0x82599680, Data, 4); // Ban 1
	memcpy((BYTE*)0x82599670, Data, 4); // Ban 2
	memcpy((BYTE*)0x82599628, Data, 4); // Ban 3
	memcpy((BYTE*)0x8259964C, Data, 4); // Ban 4
	memcpy((BYTE*)0x825996AC, Data, 4); // Ban Checks
	memcpy((BYTE*)0x825996B4, Data, 4); // Console Checks
	memcpy((BYTE*)0x82599644, Data, 4); // XUID Check
	memcpy((BYTE*)0x8259964C, Data, 4); // Other
	Sleep(500);
}

bool FindSectionInfo(char * sectionName, int * virtualAddress, int * virtualLength)
{
	int sectionInfoOffset = 0x82000000;
	while(strcmp(".rdata", (char*)sectionInfoOffset)) sectionInfoOffset+=4;
	IMAGE_SECTION_HEADER *defaultSections = (IMAGE_SECTION_HEADER*)sectionInfoOffset;

	bool succeded = false;
	*virtualAddress = *virtualLength = 0;
	for(int i = 0; strlen((char*)defaultSections[i].Name); i++)
		if(!strcmp(sectionName, (char*)defaultSections[i].Name))
		{
			*virtualAddress = _byteswap_ulong(defaultSections[i].VirtualAddress);
			*virtualLength = _byteswap_ulong(defaultSections[i].Misc.VirtualSize);
			succeded = true;
			break;
		}

		if(!succeded)
			printf("ERROR!\n");

		return succeded;
}

void * AlignedMemorySearch(char * sectionName, void * scanData, int dataLength)
{
	int sectionOffset, sectionLength;
	if(FindSectionInfo(sectionName, &sectionOffset, &sectionLength))
	{
		void * currentAddress = (void*)(0x82000000 + sectionOffset);
		while((unsigned int)currentAddress <= (0x82000000 + sectionOffset + sectionLength - dataLength)) {
			if(!memcmp(currentAddress, scanData, dataLength))
				return currentAddress;
			else
				currentAddress = (void*)((int)currentAddress + 4);
		}
	}

	printf("ERROR!\n");

	return 0;
}

void * FindFunctionBranch(void * buffer)
{
	int DifferenceInOffset = *(unsigned int*)buffer & 0x3FFFFFC;
	if(DifferenceInOffset & 0x2000000)
	{
		DifferenceInOffset = (~DifferenceInOffset + 1) & 0x3FFFFFC;
		buffer = (void*)((int)buffer - DifferenceInOffset);
	}
	else buffer = (void*)((int)buffer + DifferenceInOffset);
	return buffer;
}

__declspec(naked) void externalDLCMaps_Signature() {
	__asm {
		lis       r11, 0
			li        r3, 1
			addi      r4, r11, 0
	}
}

__declspec(naked) void disableGTCheck_Signature() {
	__asm {
		lis       r11, 0
			li        r3, 0
			addi      r4, r11, 0
	}
}

__declspec(naked) void allDLCMaps_Signature() {
	__asm {
		addi      r31, r31, 0x4C
			addi      r11, r29, 0x2A5
			cmpw      cr6, r31, r11
	}
}

char* dllDir = "Hdd:\\Tesseract.dll";
void AsmJump()
{
	XexLoadImage("Hdd:\\Tesseract.dll", 9, 0, NULL);
}

void WriteHILOToBuffer(void* buffer, int hiOffset, int loOffset, int newOffset)
{
	short firstVal = HIWORD(newOffset);
	if(newOffset & 0x8000)
		firstVal++;
	memcpy((LPVOID)((int)buffer + hiOffset), (LPCVOID)&firstVal, 2);
	firstVal = LOWORD(newOffset);
	memcpy((LPVOID)((int)buffer + loOffset), (LPCVOID)&firstVal, 2);
}

NTSTATUS XamUserGetSigninInfoHook( DWORD userIndex, DWORD flags, PXUSER_SIGNIN_INFO xSigningInfo){

	NTSTATUS ret = XamUserGetSigninInfo(userIndex, flags, xSigningInfo);

	//sprintf(xSigningInfo->szUserName,"Hellish Taco");


	//if(xamSignInfoCounter>300)
	//	xSigningInfo->dwInfoFlags = XUSER_INFO_FLAG_GUEST;
	//else 
	//	xSigningInfo->dwInfoFlags = XUSER_INFO_FLAG_LIVE_ENABLED;

	//xSigningInfo->dwGuestNumber = 0;
	//xSigningInfo->UserSigninState = eXUserSigninState_SignedInToLive;
	//xSigningInfo->dwSponsorUserIndex = 0;
	//XUID spoofedXUID = 0x000900000A8F5239;
	//memcpy(&xSigningInfo->xuid,&spoofedXUID,sizeof(XUID));
	//printf("UserSigninInfo: Spoofed XUID to %llX\r\n", spoofedXUID);
	//launchSysMsg(L"XBLH - Spoofed signin info");
	return ret;
}

HRESULT XamUserGetXUIDHook( DWORD dwUserIndex, DWORD unk, PXUID onlineOut){
	HRESULT ret = XamUserGetXUID(dwUserIndex, unk, onlineOut);

	//XUID spoofedXUID = 0x000900000A8F5239;
	//SetMemory(onlineOut, &spoofedXUID, sizeof(XUID));
	//printf("UserGetXUID: Spoofed XUID to %llX\r\n", spoofedXUID);
	return ret;
}

DWORD XamUserGetNameHook( DWORD dwUserIndex, LPSTR pUserName, DWORD cchUserName){
	DWORD ret = XamUserGetName(dwUserIndex, pUserName, cchUserName);

	//char* spoofName = "tK Burnsy";
	//SetMemory(pUserName, spoofName, strlen(spoofName));
	//sprintf(pUserName,"Hellish Taco");
	return ret;
}

// 530
DWORD XamUserCheckPrivilegeHook(DWORD dwUserIndex, XPRIVILEGE_TYPE PrivilegeType, PBOOL pfResult)
{
	if (PrivilegeType == XPRIVILEGE_TYPE::XPRIVILEGE_COMMUNICATIONS_FRIENDS_ONLY
		|| PrivilegeType == XPRIVILEGE_TYPE::XPRIVILEGE_PROFILE_VIEWING_FRIENDS_ONLY
		|| PrivilegeType == XPRIVILEGE_TYPE::XPRIVILEGE_USER_CREATED_CONTENT_FRIENDS_ONLY
		|| PrivilegeType == XPRIVILEGE_TYPE::XPRIVILEGE_PRESENCE_FRIENDS_ONLY
		|| PrivilegeType == XPRIVILEGE_TYPE::XPRIVILEGE_VIDEO_COMMUNICATIONS_FRIENDS_ONLY)
		*pfResult = TRUE;
	else
		*pfResult = TRUE;

	return 0;
}

typedef HRESULT (*pXamInputGetState)(QWORD r3,QWORD r4,QWORD r5);
pXamInputGetState XamInputGetState = (pXamInputGetState)resolveFunct(MODULE_XAM, 401);

HRESULT XamInputGetStateHook(QWORD r3,QWORD r4,QWORD r5){
	if(isFrozen){
		return 0;
	}
	HRESULT ret = XamInputGetState(r3, r4, r5);
}

static DWORD lastTitleID=0;
bool bo2_patched = 0;
VOID InitializeTitleSpecificHooks(PLDR_DATA_TABLE_ENTRY ModuleHandle) 
{
	DbgOut("[InitializeTitleSpecificHooks]\n");
	//return;
	// Hook any calls to XexGetProcedureAddress
	//PatchModuleImport(ModuleHandle, MODULE_KERNEL, 407, (DWORD)XexGetProcedureAddressHook);

	// If this module tries to load more modules, this will let us get those as well
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 408, (DWORD)XexLoadExecutableHook);

	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 409, (DWORD)XexLoadImageHook);

	//PatchModuleImport(ModuleHandle, MODULE_XAM, 0x530, (DWORD)XamUserCheckPrivilegeHook);

	PatchModuleImport(ModuleHandle, MODULE_XAM, 401, (DWORD)XamInputGetStateHook);

	XEX_EXECUTION_ID* pExecutionId = (XEX_EXECUTION_ID*)RtlImageXexHeaderField(ModuleHandle->XexHeaderBase, 0x00040006);
	if (pExecutionId == 0) return;

#ifdef SPOOF_MS_POINTS
	if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"Guide.MP.Purchase.xex") == 0) {
		DbgPrint("Applied MS Points spoof patches\n"); 
		/*SetMemory((PVOID)0x8168A7F0, data1, 28);// In Xam.xex
		SetMemory((PVOID)0x818E8CFC, data2, 4);// In Xam.xex
		SetMemory((PVOID)0x818E9034, data3, 4);// In Xam.xex
		SetMemory((PVOID)0x818ED72C, data4, 4);// In Xam.xex */
		SetMemory((PVOID)0x9015C108, data2, 4);// In Guide.MP.Purchase.xex
		XNotify(L"MS Points Spoofed");
		//ApplyPatches(NULL, PATCH_DATA_MPPURCHASE_MSPOINTS_RETAIL);
	}else{
		//wprintf(L"\r\nChecked: %s\r\n", ModuleHandle->BaseDllName);
	}
#endif

	if (pExecutionId->TitleID == COD_GHOSTS )
	{
		XNotify(L"Ghosts - Started - UNPROTECTED");
		DbgPrint("COD_GHOSTS: Last Execution ID: %08X\n", lastTitleID);
		DbgPrint("COD_GHOSTS: pExecutionId->Version: %08X\n", pExecutionId->Version);
		lastTitleID = pExecutionId->TitleID;
		bo2_patched = 0;
	} 
	else if (pExecutionId->TitleID == COD_BLACK_OPS_2  && !bo2_patched)
	{
		DWORD tu18v = 0x00001202;
		DWORD entry = (DWORD)ModuleHandle->EntryPoint;
		DbgOut("Black Ops 2 Detected\n");
		DbgOut("PatchPoint: 0x%08X\n", entry+0x10);
		if (pExecutionId->Version < tu18v){
			DbgOut("Bad Version - Less Than\n");
			return;
		}
		else if (pExecutionId->Version > tu18v)
		{
			DbgOut("Bad Version - Greater Than\n");
			return returnToDash(L"Unsupported Black Ops 2 TU");
		}
		else if (pExecutionId->Version == tu18v)
		{
			for(int i=0; i<4; i++)
			{
				if(XamUserIsOnlineEnabled(i) && !bo2_patched)
				{
					DbgOut("Bypass enabled and user logged in\n");
					//return returnToDash(L"Must start Black Ops 2 logged out");
				}
			}
		}
		isFrozen=true;
		Sleep(10000);
		isFrozen=false;

		//patchInJump((PDWORD)(entry+0x10), (DWORD)AsmJump, true);

		DbgOut("COD_BLACK_OPS_2: Last Execution ID: %08X\n", lastTitleID);
		DbgOut("COD_BLACK_OPS_2: pExecutionId->Version: %08X\n", pExecutionId->Version);
		lastTitleID = pExecutionId->TitleID;

		printf("Hooking Black Ops 2\n");
		//PatchModuleImport(ModuleHandle, MODULE_XAM, 551, (DWORD)XamUserGetSigninInfoHook);
		//PatchModuleImport(ModuleHandle, MODULE_XAM, 522, (DWORD)XamUserGetXUIDHook);
		//PatchModuleImport(ModuleHandle, MODULE_XAM, 526, (DWORD)XamUserGetNameHook);

		if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0)
		{
			DbgOut("default.xex patches not supported\n");
		}

		else if(wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0 && !bo2_patched)
		{
			DbgOut("Applying patches to default_mp.xex\n");
// 			BYTE Data[] = {0x60,0x0,0x0,0x0};
// 			memcpy((BYTE*)0x82599680,Data,4);
// 			memcpy((BYTE*)0x82599670,Data,4);
// 			memcpy((BYTE*)0x82599628,Data,4);
// 			memcpy((BYTE*)0x8259964C,Data,4);
// 			memcpy((BYTE*)0x825996AC,Data,4);
// 			memcpy((BYTE*)0x825996B4,Data,4);
// 			memcpy((BYTE*)0x82599644,Data,4);
// 			memcpy((BYTE*)0x8259964C,Data,4);
//			BlackOps2();
			char * disableGTCheckSearchString = "EXE_INVALID_GAMERTAG";
			//WriteHILOToBuffer(disableGTCheck_Signature, 2, 10, (int)AlignedMemorySearch(".rdata", disableGTCheckSearchString, strlen(disableGTCheckSearchString)));
			//memcpy((LPVOID)((int)AlignedMemorySearch(".text", disableGTCheck_Signature, 0xC) - 4), (LPCVOID)&alwaysBranchPatch, 2);

			char * externalDLCMapsSearchString = "PLATFORM_MISSINGMAP";
			//WriteHILOToBuffer(externalDLCMaps_Signature, 2, 10, (int)AlignedMemorySearch(".rdata", externalDLCMapsSearchString, strlen(externalDLCMapsSearchString)));
			int externalDLCMapsSignatureOffset = (int)AlignedMemorySearch(".text", externalDLCMaps_Signature, 0xC);
			//memcpy((LPVOID)((int)FindFunctionBranch((void*)(externalDLCMapsSignatureOffset - 0x1C)) + 0x14), (LPCVOID)&NOP, 4);//Patch Live_GetMapSource to always return 2 (disc)
			//memcpy((LPVOID)((int)FindFunctionBranch((void*)(externalDLCMapsSignatureOffset - 0x20)) + 4), (LPCVOID)&NOP, 4);//Patch Content_DoWeHaveContentPack to always return true

			int returnAllBitflags = 0x3860FFFF;
			int dlcmapoffset = (int)AlignedMemorySearch(".text", allDLCMaps_Signature, 0xC);
			//memcpy((LPVOID)((int)AlignedMemorySearch(".text", allDLCMaps_Signature, 0xC) + 0x14), (LPCVOID)&returnAllBitflags, 4);
			DbgOut("dlcmapoffset: 0x%08X\n", dlcmapoffset);

			bo2_patched = 1;
		}
		lastTitleID = pExecutionId->TitleID;
	}
	else if(pExecutionId->TitleID == DASHBOARD)
	{
		bo2_patched = 0;
	}

	else if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0){
		lastTitleID = pExecutionId->TitleID;
		bo2_patched = 0;
	}

	if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0){
		DWORD tstOffset = (DWORD)AlignedMemorySearch(".text", tstData, 24);
		DbgOut("tstOffset: 0x%08X\n", tstOffset);
	}
	else if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0){
		DWORD tstOffset = (DWORD)AlignedMemorySearch(".text", tstData, 24);
		DbgOut("tstOffset: 0x%08X\n", tstOffset);
	}
}