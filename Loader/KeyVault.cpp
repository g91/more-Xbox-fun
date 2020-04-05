#include "stdafx.h"
#include "KeyVault.h"

namespace kv
{
	namespace
	{
		KEY_VAULT keyVault;
		BYTE kvDigest[XECRYPT_SHA_DIGEST_SIZE];
		BOOL type1KV = false;
		BOOL fcrt = false;
		DWORD dwUpdateSequence = 0x00000005;

		const BYTE RetailKey19[0x10] = {
			0xE1, 0xBC, 0x15, 0x9C, 0x73, 0xB1, 0xEA, 0xE9, 0xAB, 0x31, 0x70, 0xF3, 0xAD, 0x47, 0xEB, 0xF3
		};
		const BYTE MasterKey[272] = {
			0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xDD, 0x5F, 0x49, 0x6F, 0x99, 0x4D, 0x37, 0xBB, 0xE4, 0x5B, 0x98, 0xF2, 0x5D, 0xA6, 0xB8, 0x43,
			0xBE, 0xD3, 0x10, 0xFD, 0x3C, 0xA4, 0xD4, 0xAC, 0xE6, 0x92, 0x3A, 0x79, 0xDB, 0x3B, 0x63, 0xAF,
			0x38, 0xCD, 0xA0, 0xE5, 0x85, 0x72, 0x01, 0xF9, 0x0E, 0x5F, 0x5A, 0x5B, 0x08, 0x4B, 0xAD, 0xE2,
			0xA0, 0x2A, 0x42, 0x33, 0x85, 0x34, 0x53, 0x83, 0x1E, 0xE5, 0x5B, 0x8F, 0xBF, 0x35, 0x8E, 0x63,
			0xD8, 0x28, 0x8C, 0xFF, 0x03, 0xDC, 0xC4, 0x35, 0x02, 0xE4, 0x0D, 0x1A, 0xC1, 0x36, 0x9F, 0xBB,
			0x90, 0xED, 0xDE, 0x4E, 0xEC, 0x86, 0x10, 0x3F, 0xE4, 0x1F, 0xFD, 0x96, 0xD9, 0x3A, 0x78, 0x25,
			0x38, 0xE1, 0xD3, 0x8B, 0x1F, 0x96, 0xBD, 0x84, 0xF6, 0x5E, 0x2A, 0x56, 0xBA, 0xD0, 0xA8, 0x24,
			0xE5, 0x02, 0x8F, 0x3C, 0xA1, 0x9A, 0xEB, 0x93, 0x59, 0xD7, 0x1B, 0x99, 0xDA, 0xC4, 0xDF, 0x7B,
			0xD0, 0xC1, 0x9A, 0x12, 0xCC, 0x3A, 0x17, 0xBF, 0x6E, 0x4D, 0x78, 0x87, 0xD4, 0x2A, 0x7F, 0x6B,
			0x9E, 0x2F, 0xCD, 0x8D, 0x4E, 0xF5, 0xCE, 0xC2, 0xA0, 0x5A, 0xA3, 0x0F, 0x9F, 0xAD, 0xFE, 0x12,
			0x65, 0x74, 0x20, 0x6F, 0xF2, 0x5C, 0x52, 0xE4, 0xB0, 0xC1, 0x3C, 0x25, 0x0D, 0xAE, 0xD1, 0x82,
			0x7C, 0x60, 0xD7, 0x44, 0xE5, 0xCD, 0x8B, 0xEA, 0x6C, 0x80, 0xB5, 0x1B, 0x7A, 0x0C, 0x02, 0xCE,
			0x0C, 0x24, 0x51, 0x3D, 0x39, 0x36, 0x4A, 0x3F, 0xD3, 0x12, 0xCF, 0x83, 0x8D, 0x81, 0x56, 0x00,
			0xB4, 0x64, 0x79, 0x86, 0xEA, 0xEC, 0xB6, 0xDE, 0x8A, 0x35, 0x7B, 0xAB, 0x35, 0x4E, 0xBB, 0x87,
			0xEA, 0x1D, 0x47, 0x8C, 0xE1, 0xF3, 0x90, 0x13, 0x27, 0x97, 0x55, 0x82, 0x07, 0xF2, 0xF3, 0xAA,
			0xF9, 0x53, 0x47, 0x8F, 0x74, 0xA3, 0x8E, 0x7B, 0xAE, 0xB8, 0xFC, 0x77, 0xCB, 0xFB, 0xAB, 0x8A
		};
	}

	BYTE cpuKey[0x10];

	BOOL XeKeysPkcs1Verify(const BYTE* pbHash, const BYTE* pbSig, XECRYPT_RSA* pRsa) {
		BYTE scratch[256];
		DWORD val = pRsa->cqw << 3;
		if (val <= 0x200) {
			XeCryptBnQw_SwapDwQwLeBe((QWORD*)pbSig, (QWORD*)scratch, val >> 3);
			if (XeCryptBnQwNeRsaPubCrypt((QWORD*)scratch, (QWORD*)scratch, pRsa) == 0) return FALSE;
			XeCryptBnQw_SwapDwQwLeBe((QWORD*)scratch, (QWORD*)scratch, val >> 3);
			return XeCryptBnDwLePkcs1Verify((const PBYTE)pbHash, scratch, val);
		}
		else return FALSE;
	}

	BOOL VerifyKeyVault() {

		// Get our KV Digest	
		XECRYPT_HMACSHA_STATE hmacSha;
		XeCryptHmacShaInit(&hmacSha, cpuKey, 0x10);
		XeCryptHmacShaUpdate(&hmacSha, (BYTE*)&keyVault.OddFeatures, 0xD4);
		XeCryptHmacShaUpdate(&hmacSha, (BYTE*)&keyVault.DvdKey, 0x1CF8);
		XeCryptHmacShaUpdate(&hmacSha, (BYTE*)&keyVault.CardeaCertificate, 0x2108);
		XeCryptHmacShaFinal(&hmacSha, kvDigest, XECRYPT_SHA_DIGEST_SIZE);

		// Check for RSA Signature
		type1KV = TRUE;
		for (DWORD x = 0; x < 0x100; x++) {
			if (keyVault.KeyVaultSignature[x] != NULL) {
				type1KV = FALSE;
				return TRUE;
			}
		}

		// This is a type 2 so lets verify the rsa signature
		return XeKeysPkcs1Verify(kvDigest, keyVault.KeyVaultSignature, (XECRYPT_RSA*)MasterKey);
	}

	HRESULT SetKeyVault(BYTE* KeyVault) {

		// Copy our keyvault
		memcpy(&keyVault, KeyVault, 0x4000);

		// Update our cached certificates
		SetMemory((PVOID)0x8E03A000, &keyVault.ConsoleCertificate, 0x1A8);

		// Update our cached console ID
		SetMemory((PVOID)0x8E038020, &keyVault.ConsoleCertificate.ConsoleId.abData, 5);

		// Update console ID struct hash
		BYTE newHash[XECRYPT_SHA_DIGEST_SIZE];
		XeCryptSha((BYTE*)0x8E038014, 0x3EC, NULL, NULL, NULL, NULL, newHash, XECRYPT_SHA_DIGEST_SIZE);
		SetMemory((PVOID)0x8E038000, newHash, XECRYPT_SHA_DIGEST_SIZE);

		// Get our key vault address
		QWORD kvAddress = Hvx::HvPeekQWORD(hvKvPtrRetail);

		// Preserve the console-specific obfuscation keys + DVD key. This can stop problems with the URL cache and other things.
		Hvx::HvPokeBytes(kvAddress + 0xD0, &keyVault.ConsoleObfuscationKey, 0x40);
		memcpy(keyVault.RoamableObfuscationKey, RetailKey19, 0x10);
		memcpy(keyVault.RoamableObfuscationKey, RetailKey19, 0x10);
		Hvx::HvPokeBytes(kvAddress, &keyVault, 0x4000);

		DbgPrint("SetKeyVault - KeyVault is set!\n");

		// All done
		return ERROR_SUCCESS;
	}

	HRESULT ProcessKeyVault() {

		// First lets verify our key vault to see if we have the proper cpu key
		if (VerifyKeyVault() != TRUE) {
			DbgPrint("SetKeyVault - VerifyKeyVault failed, invalid CPU key!\n");
			// return E_FAIL; // We will decide on this later!
		}

		// Set some other vars
		fcrt = (keyVault.OddFeatures & ODD_POLICY_FLAG_CHECK_FIRMWARE) != 0 ? TRUE : FALSE;
		return ERROR_SUCCESS;
	}

	HRESULT SetKeyVault(CHAR* FilePath) {

		// Read our kv from file
		MemoryBuffer mbKv;
		if (!CReadFile(FilePath, mbKv)) {
			DbgPrint("SetKeyVault - CReadFile failed");
			return E_FAIL;
		}

		// Call the real function to set the kv
		return SetKeyVault(mbKv.GetData());
	}

	HRESULT LoadKeyVault(CHAR* FilePath) {
		// Try and set our key vault
		if (SetKeyVault("HDD:\\KV.bin") != ERROR_SUCCESS)
			DbgPrint("LoadKeyVault - SetKeyVault failed\n");
		//return E_FAIL;

		// Now lets process our other stuff
		return ProcessKeyVault();
	}

	HRESULT SetMacAddress() {

		// Generate our MAC Address
		BYTE macAddress[6];
		macAddress[0] = 0x00;
		macAddress[1] = 0x1D;
		macAddress[2] = 0xD8;
		macAddress[3] = keyVault.ConsoleCertificate.ConsoleId.asBits.MacIndex3;
		macAddress[4] = keyVault.ConsoleCertificate.ConsoleId.asBits.MacIndex4;
		macAddress[5] = keyVault.ConsoleCertificate.ConsoleId.asBits.MacIndex5;

		// Lets check if our mac address is already set..
		BYTE curMacAddress[6];
		WORD settingSize = 6;
		ExGetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, curMacAddress, 6, &settingSize);
		if (memcmp(curMacAddress, macAddress, 6) == 0) {

			// Use the MAC to create unique PD.
			DWORD temp = 0;
			XeCryptSha(macAddress, 6, NULL, NULL, NULL, NULL, (BYTE*)&temp, 4);
			dwUpdateSequence |= (temp & ~0xFF);
			return ERROR_SUCCESS;
		}

		// It doesnt match so lets set it
		if (NT_SUCCESS(ExSetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, macAddress, 6))) {
			DbgOut("SetMacAddress - Rebooting to finalize install\n");
			Sleep(3000);
			HalReturnToFirmware(HalFatalErrorRebootRoutine);
		}

		// All done (Hopefully we dont get here...)
		return E_FAIL;
	}

	HRESULT ProcessCpuKey()
	{
		HANDLE hcpu = CreateFile(PATH_CPU, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hcpu == INVALID_HANDLE_VALUE)
		{
			DbgPrint("Couldn't find cpukey.bin\n");
			return E_HANDLE;
		}
		DWORD noBytesRead1;
		ReadFile(hcpu, cpuKey, 0x10, &noBytesRead1, NULL);
		CloseHandle(hcpu);
		if (cpuKey != NULL)
			return ERROR_SUCCESS;
		return E_FAIL;
	}
}