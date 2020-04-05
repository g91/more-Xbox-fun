#include "stdafx.h"
#pragma once


typedef HRESULT (*pDmSetMemory)(LPVOID lpbAddr, DWORD cb, LPCVOID lpbBuf, LPDWORD pcbRet);

class MemoryBuffer
{
public:

	MemoryBuffer( DWORD dwSize = 512 )
	{
		m_pBuffer = NULL;
		m_dwDataLength = 0;
		m_dwBufferSize = 0;

		if( ( dwSize < UINT_MAX ) && ( dwSize != 0 ) )
		{
			m_pBuffer = ( BYTE* )malloc( dwSize + 1 );    // one more char, in case when using string funcions
			if( m_pBuffer )
			{
				m_dwBufferSize = dwSize;
				m_pBuffer[0] = 0;
			}
		}
	};

	~MemoryBuffer()
	{
		if( m_pBuffer )
			free( m_pBuffer );

		m_pBuffer = NULL;
		m_dwDataLength = 0;
		m_dwBufferSize = 0;
	};

	// Add chunk of memory to buffer
	BOOL    Add( const void* p, DWORD dwSize )
	{
		if( CheckSize( dwSize ) )
		{
			memcpy( m_pBuffer + m_dwDataLength, p, dwSize );
			m_dwDataLength += dwSize;
			*( m_pBuffer + m_dwDataLength ) = 0;    // fill end zero
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	};

	// Get the data in buffer
	BYTE* GetData() const
	{
		return m_pBuffer;
	};

	// Get the length of data in buffer
	DWORD   GetDataLength() const
	{
		return m_dwDataLength;
	};

	// Rewind the data pointer to the begining
	void    Rewind()
	{
		m_dwDataLength = 0; m_pBuffer[ 0 ] = 0;
	};

	// Automatically adjust increase buffer size if necessary
	BOOL    CheckSize( DWORD dwSize )
	{
		if( m_dwBufferSize >= ( m_dwDataLength + dwSize ) )
		{
			return TRUE;    // Enough space
		}
		else
		{
			// Try to double it
			DWORD dwNewSize = max( m_dwDataLength + dwSize, m_dwBufferSize * 2 );
			BYTE* pNewBuffer = ( UCHAR* )realloc( m_pBuffer, dwNewSize + 1 );        // one more char
			if( pNewBuffer )
			{
				m_pBuffer = pNewBuffer;
				m_dwBufferSize = dwNewSize;
				return TRUE;
			}
			else
			{
				// Failed
				return FALSE;
			}
		}
	}

private:

	BYTE* m_pBuffer;

	DWORD m_dwDataLength;

	DWORD m_dwBufferSize;
};

float UnpackShortFloat(unsigned short value);

// change whether TLB memory protections are in effect
#define SET_PROT_OFF	2
#define SET_PROT_ON		3
DWORD HvxSetState(DWORD mode);

// resolve an ordinal to an address
DWORD resolveFunct(PCHAR modname, DWORD ord);

// find the Export Address Table in a given module
// only works in threads with the ability to peek crypted memory
// only tested on "xam.xex" and "xboxkrnl.exe"
//PIMAGE_EXPORT_ADDRESS_TABLE getModuleEat(char* modName);

// returns true if the file exists
BOOL fileExists(PCHAR path);

// patches in a 4 instruction jump which uses R11/scratch reg and ctr to assemble
// addr = pointer to address being patched
// dest = address of the new destination
// linked = (true = ctr branch with link used) (false = ctr branch, link register unaffected)
VOID patchInJump(PDWORD addr, DWORD dest, BOOL linked);

// hook export table ordinals of a module, anything linked after this hook is redirected to dstFun
// modName = pointer to string of the module name to alter the export table, like "xam.xex" or "xboxkrnl.exe"
// ord = ordinal number
// dstFun = address to change ordinal link address to
// returns the address of the start of the hook patched into modName@ord
// ** note that this type of hook ONLY works on things that haven't been linked by the time the patch is made
DWORD hookExportOrd(char* modName, DWORD ord, DWORD dstFun);

// hook imported jumper stubs to a different function
// modname = module with the import to patch
// impmodname = module name with the function that was imported
// ord = function ordinal to patch
// patchAddr = destination where it is patched to
// returns TRUE if hooked
// ** NOTE THIS FUNCTION MAY STILL BE BROKEN FOR MODULES WITH MULTIPLE IMPORT TABLES OF THE SAME impmodname
BOOL hookImpStub(char* modname, char* impmodname, DWORD ord, DWORD patchAddr);
DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);

// hook a function start based on address, using 8 instruction saveStub to do the deed
// addr = address of the hook
// saveStub = address of the area to create jump stub for replaced instructions
// dest = where the hook at addr is pointing to
VOID hookFunctionStart(PDWORD addr, PDWORD saveStub, DWORD dest);

// hook a function start based on ordinal, using 8 instruction saveStub to do the deed
// modName = pointer to string of the module name to alter the export table, like "xam.xex" or "xboxkrnl.exe"
// ord = ordinal number of the function to hook in module modName
// saveStub = address of the area to create jump stub for replaced instructions
// dest = where the hook at addr is pointing to
// returns the address of the start of the hook patched into modName@ord
PDWORD hookFunctionStartOrd(char* modName, DWORD ord, PDWORD saveStub, DWORD dest);

// tries to get the data segment size and start address of named module
// modName = pointer to string of the module name to alter the export table, like "xam.xex" or "xboxkrnl.exe"
// size = pointer to a DWORD to take the size from base
BYTE* getModBaseSize(char* modName, PDWORD size);

void writeDumpFile(const char* filepath, void* buf, int size);
std::string va( char *format,...);
void CreateDirectoryB(char * name);

void DbgOut(const char* text, ...);

VOID XNotify(PWCHAR pwszStringParam);

// mount a path to a drive name
HRESULT MountPath(const char* szDrive, const char* szDevice, BOOL both);

HRESULT SetMemory(VOID* Destination, VOID* Source, DWORD Length);

BOOL XeKeysPkcs1Verify(const BYTE* pbHash, const BYTE* pbSig, XECRYPT_RSA* pRsa);

BOOL CReadFile(const CHAR * FileName, MemoryBuffer &pBuffer);

VOID returnToDash(WCHAR* msg);

std::string getTime();

bool CWriteFile(LPCSTR fileName, void* data, int size);
