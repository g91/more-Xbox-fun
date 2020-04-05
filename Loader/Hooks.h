#include "stdafx.h"
#pragma once

NTSTATUS XexLoadImageHook(LPCSTR szXexName, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion, PHANDLE pHandle);
NTSTATUS XexLoadExecutableHook(PCHAR szXexName, PHANDLE pHandle, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion);
HRESULT XexStartExecutableHook(FARPROC TitleProcessInitThreadProc);
NTSTATUS XexGetModuleHandleHook(PSZ modName, PHANDLE pHandle);