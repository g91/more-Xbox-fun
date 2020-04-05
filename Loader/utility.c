#include "stdafx.h"
#include "utility.h"
#include <fstream>

#ifdef _DEBUG
#include <xbdm.h>
#endif

#pragma warning(disable:4101) // unreferenced variable warning(certain variables are only needed when compiling for XDK

#define SYS_STRING "\\System??\\%s"
#define USR_STRING "\\??\\%s"

typedef void (*XNotifyQueueUI1)(XNOTIFYQUEUEUI_TYPE exnq, DWORD dwUserIndex, ULONGLONG qwAreas, PWCHAR displayText, PVOID contextData );
XNotifyQueueUI1 XNotifyD = (XNotifyQueueUI1)resolveFunct("xam.xex", 656);

std::string va( char *format,...)
{
	char charBuffer[0x200];
	va_list arglist;
	va_start(arglist,format);
	vsprintf(charBuffer,format,arglist);
	va_end(arglist);
	return std::string(charBuffer);
}

void CreateDirectoryB(char * name)
{
	int numOfSlashes = 0;
	char tempChar;
	for(int q = 0; ; q++)
		if(name[q] == '\\') {
			if((++numOfSlashes) > 1)
			{
				tempChar = name[q+1];
				name[q+1] = 0;
				CreateDirectory(name, NULL);
				name[q+1] = tempChar;
			}
		}
		else if(!name[q]) break;
}

BOOL pfShow = (BOOL)0xDEADBEEF;  //flag to init values
BOOL pfShowMovie;
BOOL pfPlaySound;
BOOL pfShowIPTV;
VOID toggleNotify(BOOL on){
	if((int)pfShow==0xDEADBEEF) //init values
		XNotifyUIGetOptions(&pfShow, &pfShowMovie, &pfPlaySound, &pfShowIPTV);

	if(!on){
		//XNotifyUISetOptions(false, false, false, true);
		XNotifyUISetOptions(pfShow, pfShowMovie, pfPlaySound, pfShowIPTV);  //set back original values
	}else{
		XNotifyUISetOptions(true, true, true, true);  //turn on notifications so XBLSE msgs always show..
	}
	Sleep(500);
}
VOID XDoNotify(PWCHAR Message)
{
	toggleNotify(true);
	XNotifyD(XNOTIFYUI_TYPE_GENERIC, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, Message, NULL);
	toggleNotify(false);
}
VOID XNotify(std::string str)
{
	
	std::wstring wstr = std::wstring(str.begin(), str.end());
	const PWCHAR pwszStringParam = (PWCHAR)wstr.c_str();
	DbgOut("[XNotify]: %s\n", str.c_str());
	if (KeGetCurrentProcessType() != PROC_USER)
	{
		HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)XDoNotify, (LPVOID)pwszStringParam, CREATE_SUSPENDED, NULL);
		if (th == NULL) return;
		ResumeThread(th);
		DbgPrint("Notify\n");
		return;
	}
	else
		XDoNotify(pwszStringParam);	
	DbgPrint("Notify2");
}

void XNotify_Time()
{
	std::string str = getTime();
	std::wstring wstr = std::wstring(str.begin(), str.end());
	const wchar_t* wc_str = wstr.c_str();
	XNotify(str);
}

void DbgOut(const char* text, ...)
{
	char dest[0x200]; // WARNING: SYSTEM CRASH IF EXCEEDS STACK SIZE
	va_list args;
	va_start(args, text);
	vsprintf(dest, text, args);
	va_end(args);
	printf("%s", dest);
	std::ofstream log_file("usb:\\Kratistos.txt", std::ios_base::app);
	if(log_file.is_open())
		log_file<< dest;
	else
		return;
		//printf("NOT LOGGED\n");
	//printf("DONE LOG\n");
}

void writeDumpFile(const char* filepath, void* buf, int size)
{
	std::ofstream outfile(filepath, std::ios_base::out | std::ios_base::binary);
	if(outfile.is_open())
	{
		outfile.write((const char*)buf, size);
	}
	else DbgOut("FILE NOT DUMPED\n");
	outfile.close();
}

HRESULT doMountPath(const char* szDrive, const char* szDevice, const char* sysStr)
{
	STRING DeviceName, LinkName;
	CHAR szDestinationDrive[MAX_PATH];
	sprintf_s(szDestinationDrive, MAX_PATH, sysStr, szDrive);
	RtlInitAnsiString(&DeviceName, szDevice);
	RtlInitAnsiString(&LinkName, szDestinationDrive);
	ObDeleteSymbolicLink(&LinkName);
	return (HRESULT)ObCreateSymbolicLink(&LinkName, &DeviceName);
}

float UnpackShortFloat(unsigned short value)
{
	unsigned int num3;
	if ((value & -33792) == 0)
	{
		if ((value & 0x3ff) != 0)
		{
			unsigned int num2 = 0xfffffff2;
			unsigned int num = (unsigned int)(value & 0x3ff);
			while ((num & 0x400) == 0)
			{
				num2--;
				num = num << 1;
			}
			num &= 0xfffffbff;
			num3 = ((unsigned int)(((value & 0x8000) << 0x10) | ((num2 + 0x7f) << 0x17))) | (num << 13);
		}
		else
		{
			num3 = (unsigned int)((value & 0x8000) << 0x10);
		}
	}
	else
	{
		num3 = (unsigned int)((((value & 0x8000) << 0x10) | (((((value >> 10) & 0x1f) - 15) + 0x7f) << 0x17)) | ((value & 0x3ff) << 13));
	}
	return *(((float*)&num3));
}

HRESULT MountPath(const char* szDrive, const char* szDevice, BOOL both)
{
	HRESULT res;
	if(both)
	{
		res = doMountPath(szDrive, szDevice, SYS_STRING);
		res = doMountPath(szDrive, szDevice, USR_STRING);
	}
	else
	{
		if(KeGetCurrentProcessType() == PROC_SYSTEM)
			res = doMountPath(szDrive, szDevice, SYS_STRING);
		else
			res = doMountPath(szDrive, szDevice, USR_STRING);
	}
	return res;
}

PIMAGE_EXPORT_ADDRESS_TABLE getModuleEat(char* modName)
{
	PLDR_DATA_TABLE_ENTRY moduleHandle = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle(modName);
	if(moduleHandle != NULL)
	{
		DWORD ret;
		PIMAGE_XEX_HEADER xhead = (PIMAGE_XEX_HEADER)moduleHandle->XexHeaderBase;
		ret = (DWORD)RtlImageXexHeaderField(xhead, 0xE10402);
		if(ret == 0)
		{
			return xhead->SecurityInfo->ImageInfo.ExportTableAddress;
		}
	}
	return NULL;
}

DWORD resolveFunct(PCHAR modname, DWORD ord)
{
	DWORD ptr2=0;
	HANDLE hand;
	if(NT_SUCCESS(XexGetModuleHandle(modname, &hand)))
		XexGetProcedureAddress(hand, ord, &ptr2);
	return ptr2; // function not found
}

// this is how xam does it...
BOOL fileExists(PCHAR path)
{
	OBJECT_ATTRIBUTES obAtrib;
	FILE_NETWORK_OPEN_INFORMATION netInfo;
	STRING filePath;
	RtlInitAnsiString(&filePath, path); //  = 0x10
	InitializeObjectAttributes(&obAtrib, &filePath, 0x40, NULL);
	if(path[0] != '\\')
		obAtrib.RootDirectory = (HANDLE)0xFFFFFFFD;
	if(NT_SUCCESS(NtQueryFullAttributesFile(&obAtrib, &netInfo)))
	{
		// filter out directories from the result
		if((netInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
			return TRUE;
	}
	return FALSE;
}

// this one was fixed to allow busy files to be detected as existing
//BOOL fileExists(PCHAR path)
//{
//	HANDLE = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
//	if(file == INVALID_HANDLE_VALUE)
//	{
//		if(GetLastError() != 5) // inaccessible means it exists but is probably open somewhere else
//			return FALSE;
//	}
//	CloseHandle(file);
//	return TRUE;
//}

VOID patchInJump(PDWORD addr, DWORD dest, BOOL linked)
{
	DWORD writeBuffer;
	DWORD outInt;
	writeBuffer = 0x3D600000 + (((dest >> 16) & 0xFFFF) + (dest & 0x8000 ? 1 : 0)); // lis %r11, dest>>16 + 1
#ifdef _DEBUG
	DmSetMemory(&addr[0], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
	addr[0] = writeBuffer;
#endif

	writeBuffer = 0x396B0000 + (dest & 0xFFFF); // addi %r11, %r11, dest&0xFFFF
#ifdef _DEBUG
	DmSetMemory(&addr[1], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
	addr[1] = writeBuffer;
#endif

	writeBuffer = 0x7D6903A6; // mtctr %r11
#ifdef _DEBUG
	DmSetMemory(&addr[2], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
	addr[2] = writeBuffer;
#endif

	writeBuffer = 0x4E800420 | (linked ? 1 : 0); // bctr
#ifdef _DEBUG
	DmSetMemory(&addr[3], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
	addr[3] = writeBuffer;
#endif

	__dcbst(0, addr);
	__sync();
	__isync();
}

VOID patchInJump_Alt(PDWORD addr, DWORD dest, BOOL linked)
{
	DWORD writeBuffer;
	DWORD outInt;
	writeBuffer = 0x3D600000 + (((dest >> 16) & 0xFFFF) + (dest & 0x8000 ? 1 : 0)); // lis %r11, dest>>16 + 1
#ifdef _DEBUG
	DmSetMemory(&addr[0], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
	addr[0] = writeBuffer;
#endif

	writeBuffer = 0x396B0000 + (dest & 0xFFFF); // addi %r11, %r11, dest&0xFFFF
#ifdef _DEBUG
	DmSetMemory(&addr[1], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
	addr[1] = writeBuffer;
#endif

	writeBuffer = 0x7D6903A6; // mtctr %r11
#ifdef _DEBUG
	DmSetMemory(&addr[2], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
	addr[2] = writeBuffer;
#endif

	writeBuffer = 0x4E800420 | (linked ? 1 : 0); // bctr
#ifdef _DEBUG
	DmSetMemory(&addr[3], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
	addr[3] = writeBuffer;
#endif

	__dcbst(0, addr);
	__sync();
	__isync();
}

DWORD hookExportOrd(char* modName, DWORD ord, DWORD dstFun)
{
	PIMAGE_EXPORT_ADDRESS_TABLE expbase = getModuleEat(modName);
	if(expbase != NULL)
	{
		DWORD modOffset = (expbase->ImageBaseAddress)<<16;
		DWORD origOffset = (expbase->ordOffset[ord-1])+modOffset;
		expbase->ordOffset[ord-1] = dstFun-modOffset;
		__dcbst(0, &expbase->ordOffset[ord-1]);
		__sync();
		__isync();
		return origOffset;
	}
	return 0;
}

DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) {

	// First resolve this imports address
	DWORD address = (DWORD)resolveFunct(ImportedModuleName, Ordinal);
	if(address == NULL)
		return S_FALSE;

	// Get our header field from this module
	VOID* headerBase = Module->XexHeaderBase;
	PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(headerBase, 0x000103FF);
	if(importDesc == NULL)
		return S_FALSE;

	// Our result
	DWORD result = 2; // No occurances patched

	// Get our string table position
	CHAR* stringTable = (CHAR*)(importDesc + 1);

	// Get our first entry
	XEX_IMPORT_TABLE_ORG* importTable = (XEX_IMPORT_TABLE_ORG*)(stringTable + importDesc->NameTableSize);

	// Loop through our table
	for(DWORD x = 0; x < importDesc->ModuleCount; x++) {

		// Go through and search all addresses for something that links
		DWORD* importAdd = (DWORD*)(importTable + 1);
		for(DWORD y = 0; y < importTable->ImportTable.ImportCount; y++) {

			// Check the address of this import
			DWORD value = *((DWORD*)importAdd[y]);
			if(value == address) {

				// We found a matching address address
				memcpy((DWORD*)importAdd[y], &PatchAddress, 4);
				DWORD newCode[4];
				patchInJump(newCode, PatchAddress, FALSE);
				memcpy((DWORD*)importAdd[y + 1], newCode, 16);

				// We patched at least one occurence
				result = S_OK;
			}
		}

		// Goto the next table
		importTable = (XEX_IMPORT_TABLE_ORG*)(((BYTE*)importTable) + importTable->TableSize);
	}

	// Return our result
	return result;
}

BOOL hookImpStub(char* modname, char* impmodname, DWORD ord, DWORD patchAddr)
{
	LDR_DATA_TABLE_ENTRY* moduleHandle = (LDR_DATA_TABLE_ENTRY*)GetModuleHandle(modname);
	return (moduleHandle == NULL) ? S_FALSE : PatchModuleImport(moduleHandle, impmodname, ord, patchAddr);
}

BYTE* getModBaseSize(char* modName, PDWORD size)
{
	PLDR_DATA_TABLE_ENTRY ldat;
	ldat = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle(modName);
	if(ldat != NULL)
	{
		if(ldat->EntryPoint > ldat->ImageBase)
			size[0] = ((DWORD)ldat->EntryPoint-(DWORD)ldat->ImageBase);
		else
			size[0] = ldat->SizeOfFullImage;
		return (BYTE*)ldat->ImageBase;
	}
	return NULL;
}

VOID __declspec(naked) GLPR_FUN(VOID)
{
	__asm{
		std     r14, -0x98(sp)
		std     r15, -0x90(sp)
		std     r16, -0x88(sp)
		std     r17, -0x80(sp)
		std     r18, -0x78(sp)
		std     r19, -0x70(sp)
		std     r20, -0x68(sp)
		std     r21, -0x60(sp)
		std     r22, -0x58(sp)
		std     r23, -0x50(sp)
		std     r24, -0x48(sp)
		std     r25, -0x40(sp)
		std     r26, -0x38(sp)
		std     r27, -0x30(sp)
		std     r28, -0x28(sp)
		std     r29, -0x20(sp)
		std     r30, -0x18(sp)
		std     r31, -0x10(sp)
		stw     r12, -0x8(sp)
		blr
	}
}

DWORD relinkGPLR(int offset, PDWORD saveStubAddr, PDWORD orgAddr)
{
	DWORD inst = 0, repl;
	int i;
	PDWORD saver = (PDWORD)GLPR_FUN;
	// if the msb is set in the instruction, set the rest of the bits to make the int negative
	if(offset&0x2000000)
		offset = offset|0xFC000000;
	//DbgPrint("frame save offset: %08x\n", offset);
	repl = orgAddr[offset/4];
	//DbgPrint("replacing %08x\n", repl);
	for(i = 0; i < 20; i++)
	{
		if(repl == saver[i])
		{
			int newOffset = (int)&saver[i]-(int)saveStubAddr;
			inst = 0x48000001|(newOffset&0x3FFFFFC);
			//DbgPrint("saver addr: %08x savestubaddr: %08x\n", &saver[i], saveStubAddr);
		}
	}
	//DbgPrint("new instruction: %08x\n", inst);
	return inst;
}

VOID hookFunctionStart(PDWORD addr, PDWORD saveStub, DWORD dest)
{
	if((saveStub != NULL)&&(addr != NULL))
	{
		int i;
		DWORD addrReloc = (DWORD)(&addr[4]);// replacing 4 instructions with a jump, this is the stub return address
		//DbgOut("hooking addr: %08x savestub: %08x dest: %08x addreloc: %08x\n", addr, saveStub, dest, addrReloc);
		// build the stub
		// make a jump to go to the original function start+4 instructions
		DWORD writeBuffer;
		DWORD outInt;

		writeBuffer = 0x3D600000 + (((addrReloc >> 16) & 0xFFFF) + (addrReloc & 0x8000 ? 1 : 0)); // lis %r11, dest>>16 + 1
#ifdef _DEBUG
		DmSetMemory(&saveStub[0], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
		saveStub[0] = writeBuffer;
#endif

		writeBuffer = 0x396B0000 + (addrReloc & 0xFFFF); // addi %r11, %r11, dest&0xFFFF
#ifdef _DEBUG
		DmSetMemory(&saveStub[1], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
		saveStub[1] = writeBuffer;
#endif

		writeBuffer = 0x7D6903A6; // mtctr %r11
#ifdef _DEBUG
		DmSetMemory(&saveStub[2], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
		saveStub[2] = writeBuffer;
#endif

		// instructions [3] through [6] are replaced with the original instructions from the function hook
		// copy original instructions over, relink stack frame saves to local ones
		for(i = 0; i<4; i++)
		{
			writeBuffer = ((addr[i]&0x48000003) == 0x48000001) ? relinkGPLR((addr[i]&~0x48000003), &saveStub[i+3], &addr[i]) : addr[i];
#ifdef _DEBUG
				DmSetMemory(&saveStub[i+3], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
				saveStub[i+3] = writeBuffer;
#endif
		}
		writeBuffer = 0x4E800420; // bctr
#ifdef _DEBUG
		DmSetMemory(&saveStub[7], 4, &writeBuffer, &outInt);
#elif defined(NDEBUG)
		saveStub[7] = writeBuffer;
#endif
		__dcbst(0, saveStub);
		__sync();
		__isync();

		//DbgPrint("savestub:\n");
		//for(i = 0; i < 8; i++)
		//{
		//	DbgPrint("PatchDword(0x%08x, 0x%08x);\n", &saveStub[i], saveStub[i]);
		//}
		// patch the actual function to jump to our replaced one
		patchInJump(addr, dest, FALSE);
	}
}

PDWORD hookFunctionStartOrd(char* modName, DWORD ord, PDWORD saveStub, DWORD dest)
{
	PDWORD addr = (PDWORD)resolveFunct(modName, ord);
	if(addr != NULL)
		hookFunctionStart(addr, saveStub, dest);
	return addr;
}
pDmSetMemory DevSetMemory = NULL;
HRESULT SetMemory(VOID* Destination, VOID* Source, DWORD Length) {

	// Try to resolve our function
	if(DevSetMemory == NULL)
		DevSetMemory = (pDmSetMemory)resolveFunct("xbdm.xex", 40);

	// Now lets try to set our memory
	if(DevSetMemory == NULL) {
		memcpy(Destination, Source, Length);
		return ERROR_SUCCESS;
	} else {
		if(DevSetMemory(Destination, Length, Source, NULL) == MAKE_HRESULT(0, 0x2da, 0))
			return ERROR_SUCCESS;
	}

	// We have a problem..
	return E_FAIL;
}

BOOL CReadFile(const CHAR * FileName, MemoryBuffer &pBuffer) {

	HANDLE hFile; DWORD dwFileSize, dwNumberOfBytesRead;
	hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE) {
		DbgPrint("CReadFile - CreateFile failed");
		return FALSE;
	}
	dwFileSize = GetFileSize(hFile, NULL);
	PBYTE lpBuffer = (BYTE*)malloc(dwFileSize);
	if(lpBuffer == NULL) {
		CloseHandle(hFile);
		DbgPrint("CReadFile - malloc failed");
		return FALSE;
	}
	if(ReadFile(hFile, lpBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) == FALSE) {
		free(lpBuffer);
		CloseHandle(hFile);
		DbgPrint("CReadFile - ReadFile failed");
		return FALSE;
	}
	else if (dwNumberOfBytesRead != dwFileSize) {
		free(lpBuffer);
		CloseHandle(hFile);
		DbgPrint("CReadFile - Failed to read all the bytes");
		return FALSE;
	}
	CloseHandle(hFile);
	pBuffer.Add(lpBuffer, dwFileSize);
	free(lpBuffer);
	return TRUE;
}

VOID returnToDashThread(VOID){
	Sleep(3000);
	XSetLaunchData(NULL, 0);
	XamLoaderLaunchTitleEx(XLAUNCH_KEYWORD_DEFAULT_APP, NULL, NULL, 0);
}

static std::string sysMsgBuffer;
VOID sysMsgThreadDelay(std::string msg){
	Sleep(8000);
	XNotify(msg);
}

VOID sysMsgThread(std::string msg){
	XNotify(msg);
}

VOID launchSysMsg(std::string msg, int delay){
	sysMsgBuffer = msg;
	HANDLE hThread;
	DWORD dwThreadId;
	if(delay!=60000 && delay>0){
		Sleep(delay);
		ExCreateThread(&hThread, 0, &dwThreadId, (VOID*) XapiThreadStartup , (LPTHREAD_START_ROUTINE)sysMsgThread, &sysMsgBuffer, 0x2);
	}else
		ExCreateThread(&hThread, 0, &dwThreadId, (VOID*) XapiThreadStartup , (LPTHREAD_START_ROUTINE)sysMsgThreadDelay, &sysMsgBuffer, 0x2);

	XSetThreadProcessor( hThread, 4 );
	ResumeThread(hThread);
	CloseHandle(hThread);
}

VOID returnToDash(std::string msg){
	HANDLE hThread;
	DWORD dwThreadId;
	hThread = CreateThread( 0, 0, (LPTHREAD_START_ROUTINE)returnToDashThread, 0, CREATE_SUSPENDED, &dwThreadId );
	XSetThreadProcessor(hThread, 4);
	SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
	ResumeThread(hThread);
	CloseHandle(hThread);
	if(!msg.empty()) launchSysMsg(msg, 0);
	Sleep(500);
}

std::string getTime()
{
	SYSTEMTIME st;
	GetSystemTime(&st);
	//return va("%d.%d.%d-%d.%d.%d", st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wMilliseconds);
	std::ostringstream os;
	os << st.wMonth << "." << st.wDay << "." << st.wYear << "-" << st.wHour << "." << st.wMinute << "." << st.wMilliseconds;
	return os.str();
}

bool CWriteFile(LPCSTR fileName, void* data, int size)
{
	HANDLE fileHandle = CreateFile(fileName, GENERIC_WRITE,
		FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if( fileHandle == INVALID_HANDLE_VALUE)
	{
		DbgOut("Error Creating File: \"%s\"\n", fileName);
		return false;
	}
	DWORD Out = 0;
	if (WriteFile( fileHandle, data, size, &Out, NULL))
	{
		CloseHandle( fileHandle );
		//printf("File Size: 0x%X\nBYTES WRITTEN: 0x%X\n", size, Out);
		return true;
	}
	DbgOut("Could not save data for file: \"%s\"", fileName);
	CloseHandle( fileHandle );
	return false;
}

bool CReadFile(LPCSTR filename, PVOID buffer, DWORD size)
{
	if (!fileExists((PCHAR)filename))
		return false;
	HANDLE file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		DbgOut("Couldn't open %s\n", filename);
		return false;
	}
	DWORD noBytesRead;
	ReadFile(file, buffer, size, &noBytesRead, NULL);
	CloseHandle(file);
	if (noBytesRead <= 0)
		return false;
	return true;
}

bool IsUserSignedIn()
{
	for (int i = 0; i<4; i++)
	{
		if (XamUserIsOnlineEnabled(i))
		{
			return true;
		}
	}
	return false;
}

void arrPrintX(PBYTE pbArray, DWORD cbArray)
{
	for (int i = 0; i < cbArray; i++)
	{
		printf("%02X", pbArray[i]);
		if (i != cbArray - 1)
			printf(" ");
	}
}

void arrPrintXln(PBYTE pbArray, DWORD cbArray)
{
	for (int i = 0; i < cbArray; i++)
	{
		printf("%02X", pbArray[i]);
		if (i != cbArray - 1)
			printf(" ");
	}
	printf("\n");
}