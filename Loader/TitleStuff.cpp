#include "stdafx.h"
#include "TitleStuff.h"
#include "Hooks.h"
#include "Settings.h"

int NOP = 0x60000000;
short alwaysBranchPatch = 0x4800;
static bool isFrozen = false;
#define SPOOF_MS_POINTS

BYTE tstData[24] = { 0x7D, 0x88, 0x02, 0xA6, 0x91, 0x81, 0xFF, 0xF8, 0x94, 0x21, 0xFF, 0xA0, 0x38, 0xC1, 0x00, 0x50, 0x38, 0xA0, 0x00, 0x00, 0x38, 0x80, 0x00, 0x09 };

namespace msp
{
#ifdef SPOOF_MS_POINTS
	BYTE data[28] = { 0x38, 0x80, 0x00, 0x05, 0x80, 0x63, 0x00, 0x1C, 0x90, 0x83, 0x00, 0x04, 0x38, 0x80, 0x27, 0x0F, 0x90, 0x83, 0x00, 0x08, 0x38, 0x60, 0x00, 0x00, 0x4E, 0x80, 0x00, 0x20 };
	BYTE nop[4] = { 0x60, 0x00, 0x00, 0x00 };
	BYTE branch[4] = { 0x48, 0x00, 0x00, 0xC8 };
	BYTE lR11Low[4] = { 0x39, 0x60, 0x00, 0x00 };

	// 17511
	int OffsetGuide = 0x9015C108;
	int OffsetXam1 = 0x8168A7F0;
	int OffsetXam2 = 0x818E8CFC;
	int OffsetXam3 = 0x818E9034;
	int OffsetXam4 = 0x818ED72C;
#endif // SPOOF_MS_POINTS

	// Must be applied every time the payment window is loaded and open
	void PatchMSP_Guide()
	{
#ifdef SPOOF_MS_POINTS
		DbgPrint("Patching MS Points in Guide\n");
		SetMemory((PVOID)OffsetGuide, nop, 4); // In Guide.MP.Purchase.xex
		XNotify("MS Points Spoofed");
#endif // SPOOF_MS_POINTS
		return;
	}

	// Can be applied on boot or when ever a purchase needs to be made
	void PatchMSP_Xam()
	{
#ifdef SPOOF_MS_POINTS
		DbgPrint("Patching MS Points in xam\n");
		SetMemory((PVOID)OffsetXam1, data, 28); // In Xam.xex
		SetMemory((PVOID)OffsetXam2, nop, 4); // In Xam.xex
		SetMemory((PVOID)OffsetXam3, branch, 4); // In Xam.xex
		SetMemory((PVOID)OffsetXam4, lR11Low, 4); // In Guide.MP.Purchase.xex
#endif // SPOOF_MS_POINTS
		return;
	}
}

namespace xam
{
	typedef HRESULT(*pXamInputGetState)(QWORD r3, QWORD r4, QWORD r5);
	pXamInputGetState XamInputGetState = (pXamInputGetState)resolveFunct(MODULE_XAM, 401);

	HRESULT XamInputGetStateHook(QWORD r3, QWORD r4, QWORD r5) {
		if (isFrozen) {
			return 0;
		}
		return XamInputGetState(r3, r4, r5);
	}

	NTSTATUS XamUserGetSigninInfoHook(DWORD userIndex, DWORD flags, PXUSER_SIGNIN_INFO xSigningInfo) {

		NTSTATUS ret = XamUserGetSigninInfo(userIndex, flags, xSigningInfo);
		sprintf(xSigningInfo->szUserName,Settings::UserName);


		//if(xamSignInfoCounter>300)
		//	xSigningInfo->dwInfoFlags = XUSER_INFO_FLAG_GUEST;
		//else 
		//	xSigningInfo->dwInfoFlags = XUSER_INFO_FLAG_LIVE_ENABLED;

		xSigningInfo->dwGuestNumber = 0;
		xSigningInfo->UserSigninState = eXUserSigninState_SignedInToLive;
		xSigningInfo->dwSponsorUserIndex = 0;
		memcpy(&xSigningInfo->xuid,&Settings::UserXUID,sizeof(XUID));
		//printf("UserSigninInfo: Spoofed XUID to %llX\r\n", spoofedXUID);
		return ret;
	}

	HRESULT XamUserGetXUIDHook(DWORD dwUserIndex, DWORD unk, PXUID onlineOut) {
		HRESULT ret = XamUserGetXUID(dwUserIndex, unk, onlineOut);
		SetMemory(onlineOut, &Settings::UserXUID, sizeof(XUID));
		//printf("UserGetXUID: Spoofed XUID to %llX\r\n", spoofedXUID);
		return ret;
	}

	DWORD XamUserGetNameHook(DWORD dwUserIndex, LPSTR pUserName, DWORD cchUserName) {
		DWORD ret = XamUserGetName(dwUserIndex, pUserName, cchUserName);
		sprintf(pUserName, Settings::UserName);
		return ret;
	}

	// 530
	DWORD XamUserCheckPrivilegeHook(DWORD dwUserIndex, XPRIVILEGE_TYPE PrivilegeType, PBOOL pfResult)
	{
		if (PrivilegeType == XPRIVILEGE_COMMUNICATIONS_FRIENDS_ONLY
			|| PrivilegeType == XPRIVILEGE_PROFILE_VIEWING_FRIENDS_ONLY
			|| PrivilegeType == XPRIVILEGE_USER_CREATED_CONTENT_FRIENDS_ONLY
			|| PrivilegeType == XPRIVILEGE_PRESENCE_FRIENDS_ONLY
			|| PrivilegeType == XPRIVILEGE_VIDEO_COMMUNICATIONS_FRIENDS_ONLY)
			*pfResult = FALSE;
		else
			*pfResult = TRUE;

		return 0;
	}
}

namespace bo2
{
	void StartBO2OnRetail(PLDR_DATA_TABLE_ENTRY ModuleHandle, XEX_EXECUTION_ID* pExecutionId)
	{
		DWORD tu18v = 0x00001202;
		DWORD entry = (DWORD)ModuleHandle->EntryPoint;
		DbgOut("Black Ops 2 Detected\n");
		DbgOut("PatchPoint: 0x%08X\n", entry + 0x10);
		if (pExecutionId->Version < tu18v) {
			DbgOut("Bad Version - Please Update Your Game\n");
			return;
		}
		else if (pExecutionId->Version > tu18v)
		{
			DbgOut("Bad Version - New TU\n");
			return returnToDash("Unsupported Black Ops 2 TU");
		}

		//patchInJump((PDWORD)(entry+0x10), (DWORD)AsmJump, true);

		printf("Hooking Black Ops 2\n");
		
		if (Settings::hookUserInfo)
		{
			PatchModuleImport(ModuleHandle, MODULE_XAM, 522, (DWORD)xam::XamUserGetXUIDHook);
			PatchModuleImport(ModuleHandle, MODULE_XAM, 526, (DWORD)xam::XamUserGetNameHook);
		}
		if (Settings::hookUserGetInfo)
			PatchModuleImport(ModuleHandle, MODULE_XAM, 551, (DWORD)xam::XamUserGetSigninInfoHook);

		if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0)
		{
			DbgOut("default.xex patches not supported\n");
		}

		else if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0)
		{
			DbgOut("Applying patches to default_mp.xex\n");
			if (Settings::bypassBO2)
				bo2::BO2Bypass1();
		}
	}

	void BO2Bypass1()
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
	void BO2Bypass2()
	{
		BYTE Data[] = { 0x60, 0x00, 0x00, 0x00 };
		memcpy((BYTE*)0x82599680,Data,4);
		memcpy((BYTE*)0x82599670,Data,4);
		memcpy((BYTE*)0x82599628,Data,4);
		memcpy((BYTE*)0x8259964C,Data,4);
		memcpy((BYTE*)0x825996AC,Data,4);
		memcpy((BYTE*)0x825996B4,Data,4);
		memcpy((BYTE*)0x82599644,Data,4);
		memcpy((BYTE*)0x8259964C,Data,4);
	}
}

namespace ghosts
{
	void StartGhostsOnRetail(PLDR_DATA_TABLE_ENTRY ModuleHandle, XEX_EXECUTION_ID* pExecutionId)
	{
		XNotify("Ghosts - Started - UNPROTECTED");
	}
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
static int dllDirAddy = (int)(&dllDir[0]);
void __declspec(naked) AsmJump()
{
	__asm
	{
		stwu	r1, -0x1F0(r1)
		mr		r3, dllDirAddy
	}
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





static DWORD lastTitleID=0;
VOID InitializeTitleSpecificHooks(PLDR_DATA_TABLE_ENTRY ModuleHandle) 
{
	//DbgOut("[InitializeTitleSpecificHooks]\n");
	char oName[128];
	wcstombs(oName, ModuleHandle->BaseDllName.Buffer, ModuleHandle->BaseDllName.Length);
	oName[ModuleHandle->BaseDllName.Length] = 0;
	DbgOut("TitleHook: %s\n", oName);


	//PatchModuleImport(ModuleHandle, MODULE_KERNEL, 407, (DWORD)XexGetProcedureAddressHook);
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 408, (DWORD)XexLoadExecutableHook);
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 409, (DWORD)XexLoadImageHook);
	//PatchModuleImport(ModuleHandle, MODULE_XAM, 0x530, (DWORD)XamUserCheckPrivilegeHook);
	PatchModuleImport(ModuleHandle, MODULE_XAM, 401, (DWORD)xam::XamInputGetStateHook);

	XEX_EXECUTION_ID* pExecutionId = (XEX_EXECUTION_ID*)RtlImageXexHeaderField(ModuleHandle->XexHeaderBase, 0x00040006);
	if (pExecutionId == 0) return;

	if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"Guide.MP.Purchase.xex") == 0)
		if (Settings::spoofMSP)
			msp::PatchMSP_Guide(); //ApplyPatches(NULL, PATCH_DATA_MPPURCHASE_MSPOINTS_RETAIL);

	if (pExecutionId->TitleID == COD_GHOSTS )
	{
		if (!Settings::skipGhosts)
			ghosts::StartGhostsOnRetail(ModuleHandle, pExecutionId);
		lastTitleID = pExecutionId->TitleID;
	} 

	else if (pExecutionId->TitleID == COD_BLACK_OPS_2)
	{
		if (!Settings::skipBO2)
			bo2::StartBO2OnRetail(ModuleHandle, pExecutionId);
		lastTitleID = pExecutionId->TitleID;
	}

	else if(pExecutionId->TitleID == DASHBOARD)
		DbgPrint("Dashboard\n");

	else if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0)
		lastTitleID = pExecutionId->TitleID;

	/*
	// Testing bellow
	if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0)
	{
		DWORD tstOffset = (DWORD)AlignedMemorySearch(".text", tstData, 24);
		DbgOut("tstOffset: 0x%08X\n", tstOffset);
	}
	else if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0)
	{
		DWORD tstOffset = (DWORD)AlignedMemorySearch(".text", tstData, 24);
		DbgOut("tstOffset: 0x%08X\n", tstOffset);
	}
	else if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"Default.xex") == 0)
	{
		DWORD tstOffset = (DWORD)AlignedMemorySearch(".text", tstData, 24);
		DbgOut("tstOffset: 0x%08X\n", tstOffset);
	}*/
}