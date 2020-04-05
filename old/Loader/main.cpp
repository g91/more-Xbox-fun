/*#include <xtl.h>
#include <xbox.h>
#include <xam.h>
#include <stdio.h>
#include <stdlib.h>
#include <d3d9.h>
//#include "kernel.h"
//#include "XeCrypt.h"
#include "utility.h"*/
#include "stdafx.h"

#define DbgPrint DbgOut
#define DBGBUILD true
//#define SPOOF_MS_POINTS
//#define ADDRESSDUMP

#define PATH_KV "Hdd:\\KV.bin"
#define PATH_CPU "Hdd:\\cpukey.bin"

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

// current 17511 challenge
BYTE ChallengeHash[0x10] = {
	0x60, 0x1D, 0x32, 0x4B, 0x53, 0xFA, 0x35, 0xFF, 0xB7, 0x26, 0x20, 0x36, 0xC2, 0xC4, 0xF8, 0x3B
};

void start()
{
	DbgOut("[Loader]: Start function entered\n");
	//if(!hookImpStub("xam.xex", "xboxkrnl.exe", 607, (DWORD)XeKeysExecuteHook))
		//HalReturnToFirmware(6);
	while(1)
	{
		printf("Loop active\n");
		Sleep(5000);
	}
}

BOOL APIENTRY DllMain(HANDLE hInstDLL, DWORD reason, LPVOID lpReserved){
	HANDLE	hThread;
	DWORD	hThreadId;
	switch(reason)
	{
	case DLL_PROCESS_ATTACH:
		printf("[Loader]: Attached\n");
		MountPath("hdd:", "\\Device\\Harddisk0\\Partition1\\", false);
		MountPath("usb:", "\\Device\\Mass0\\", false);
		DbgOut("-----------------------TEST-----------------------\n");
		ExCreateThread(&hThread, 0, &hThreadId, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)start, NULL, 0x2);
		XSetThreadProcessor(hThread, 4); ResumeThread(hThread); CloseHandle(hThread);
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