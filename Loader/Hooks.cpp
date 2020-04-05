#include "stdafx.h"
#include "Hooks.h"
#include "TitleStuff.h"

NTSTATUS XexLoadImageHook(LPCSTR szXexName, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion, PHANDLE pHandle)
{
	printf("XexLoadImage: %s\n", szXexName);
	// Call our load function with our own handle pointer, just in case the original is null
	HANDLE mHandle = NULL;
	NTSTATUS result = XexLoadImage(szXexName, dwModuleTypeFlags, dwMinimumVersion, &mHandle);
	if (pHandle != NULL) *pHandle = mHandle;
	// If successesful, let's do our patches, passing our handle
	if (NT_SUCCESS(result)) InitializeTitleSpecificHooks((PLDR_DATA_TABLE_ENTRY)mHandle);	
	// All done
	return result;
}

NTSTATUS XexLoadExecutableHook(PCHAR szXexName, PHANDLE pHandle, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion)
{
	printf("[XexLoadExecutableHook]\n");
	// Call our load function with our own handle pointer, just in case the original is null
	HANDLE mHandle = NULL;
	NTSTATUS result = XexLoadExecutable(szXexName, &mHandle, dwModuleTypeFlags, dwMinimumVersion);
	if (pHandle != NULL) *pHandle = mHandle;
	// If successesful, let's do our patches, passing our handle
	if (NT_SUCCESS(result)) InitializeTitleSpecificHooks((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle);		
	// All done
	return result;
}

HRESULT XexStartExecutableHook(FARPROC TitleProcessInitThreadProc)
{
	return XexStartExecutable(TitleProcessInitThreadProc);
}

NTSTATUS XexGetModuleHandleHook(PSZ modName, PHANDLE pHandle)
{
	printf("[XexGetModuleHandleHook]\n");
	if (strcmp(modName, "Loader.xex") == 0)
	{
		DbgOut("XBDM Spoofed\n");
		return 0;
	}
	else
		return XexGetModuleHandle(modName, pHandle);
}