#include <idc.idc>
 
static GetSyscallName( id )
{
    if(        id == 0x00000000)    return "HvxGetVersions";//
    else if(id == 0x00000001)    return "HvxStartupProcessors";//
    else if(id == 0x00000002)    return "HvxQuiesceProcessor";//
    else if(id == 0x00000003)    return "HvxFlushEntireTb";//
    else if(id == 0x00000004)    return "HvxFlushSingleTb";//
    else if(id == 0x00000005)    return "HvxRelocateAndFlush";
    else if(id == 0x00000006)    return "HvxGetSpecialPurposeRegister";//
    else if(id == 0x00000007)    return "HvxSetSpecialPurposeRegister";//
    else if(id == 0x00000008)    return "HvxGetSocRegister";//
    else if(id == 0x00000009)    return "HvxSetSocRegister";//
    else if(id == 0x0000000A)    return "HvxSetTimeBaseToZero";//
    else if(id == 0x0000000B)    return "HvxZeroPage";//
    else if(id == 0x0000000C)    return "HvxFlushDcacheRange";//
    else if(id == 0x0000000D)    return "HvxPostOutput";//
    else if(id == 0x0000000E)    return "HvxEnablePPUPerformanceMonitor";//
    else if(id == 0x0000000F)    return "HvxGetImagePageTableEntry";//
    else if(id == 0x00000010)    return "HvxSetImagePageTableEntry";//
    else if(id == 0x00000011)    return "HvxCreateImageMapping";//
    else if(id == 0x00000012)    return "HvxMapImagePage";//
    else if(id == 0x00000013)    return "HvxCompleteImageMapping";//
    else if(id == 0x00000014)    return "HvxLoadImageData";//
    else if(id == 0x00000015)    return "HvxFinishImageDataLoad";//
    else if(id == 0x00000016)    return "HvxStartResolveImports";//
    else if(id == 0x00000017)    return "HvxResolveImports";//
    else if(id == 0x00000018)    return "HvxFinishImageLoad";//
    else if(id == 0x00000019)    return "HvxAbandonImageLoad";//
    else if(id == 0x0000001A)    return "HvxUnmapImagePages";//
    else if(id == 0x0000001B)    return "HvxUnmapImage";//
    else if(id == 0x0000001C)    return "HvxUnmapImageRange";//
    else if(id == 0x0000001D)    return "HvxCreateUserMode";//
    else if(id == 0x0000001E)    return "HvxDeleteUserMode";//
    else if(id == 0x0000001F)    return "HvxFlushUserModeTb";//
    else if(id == 0x00000020)    return "HvxSetPowerMode";//
    else if(id == 0x00000021)    return "HvxShadowBoot";
    else if(id == 0x00000022)    return "HvxBlowFuses";//
    else if(id == 0x00000023)    return "HvxFsbInterrupt";//
    else if(id == 0x00000024)    return "HvxLockL2";//
    else if(id == 0x00000025)    return "HvxDvdAuthBuildNVPage";//
    else if(id == 0x00000026)    return "HvxDvdAuthVerifyNVPage";//
    else if(id == 0x00000027)    return "HvxDvdAuthRecordAuthenticationPage";//
    else if(id == 0x00000028)    return "HvxDvdAuthRecordXControl";//
    else if(id == 0x00000029)    return "HvxDvdAuthGetAuthPage";//
    else if(id == 0x0000002A)    return "HvxDvdAuthVerifyAuthPage";//
    else if(id == 0x0000002B)    return "HvxDvdAuthGetNextLBAIndex";//
    else if(id == 0x0000002C)    return "HvxDvdAuthVerifyLBA";//
    else if(id == 0x0000002D)    return "HvxDvdAuthClearDiscAuthInfo";//
    else if(id == 0x0000002E)    return "HvxKeysInitialize";//
    else if(id == 0x0000002F)    return "HvxKeysGetKeyProperties";//
    else if(id == 0x00000030)    return "HvxKeysGetStatus";//
    else if(id == 0x00000031)    return "HvxKeysGenerateRandomKey";//
    else if(id == 0x00000032)    return "HvxKeysGetFactoryChallenge";//
    else if(id == 0x00000033)    return "HvxKeysSetFactoryResponse";//
    else if(id == 0x00000034)    return "HvxKeysSaveBootLoader";//
    else if(id == 0x00000035)    return "HvxKeysSaveKeyVault";//
    else if(id == 0x00000036)    return "HvxKeysSetKey";//
    else if(id == 0x00000037)    return "HvxKeysGetKey";//
    else if(id == 0x00000038)    return "HvxKeysGetDigest";//
    else if(id == 0x00000039)    return "HvxKeysRsaPrvCrypt";//
    else if(id == 0x0000003A)    return "HvxKeysHmacSha";//
    else if(id == 0x0000003B)    return "HvxKeysAesCbc";//
    else if(id == 0x0000003C)    return "HvxKeysDes2Cbc";//
    else if(id == 0x0000003D)    return "HvxKeysDesCbc";//
    else if(id == 0x0000003E)    return "HvxKeysObscureKey";//
    else if(id == 0x0000003F)    return "HvxKeysSaveSystemUpdate";//
    else if(id == 0x00000040)    return "HvxKeysExecute";//
    else if(id == 0x00000041)    return "HvxDvdAuthTestMode";//
    else if(id == 0x00000042)    return "HvxEnableTimebase";//
    else if(id == 0x00000043)    return "HvxHdcpCalculateMi";//
    else if(id == 0x00000044)    return "HvxHdcpCalculateAKsvSignature";//
    else if(id == 0x00000045)    return "HvxHdcpCalculateBKsvSignature";//
    else if(id == 0x00000046)    return "HvxSetRevocationList";//
    else if(id == 0x00000047)    return "HvxEncryptedAllocationReserve";//
    else if(id == 0x00000048)    return "HvxEncryptedAllocationMap";//
    else if(id == 0x00000049)    return "HvxEncryptedAllocationUnmap";//
    else if(id == 0x0000004A)    return "HvxEncryptedAllocationRelease";//
    else if(id == 0x0000004B)    return "HvxEncryptedSweepAddressRange";//
    else if(id == 0x0000004C)    return "HvxKeysExCreateKeyVault";//
    else if(id == 0x0000004D)    return "HvxKeysExLoadKeyVault"; //
    else if(id == 0x0000004E)    return "HvxKeysExSaveKeyVault";//
    else if(id == 0x0000004F)    return "HvxKeysExSetKey";//
    else if(id == 0x00000050)    return "HvxKeysExGetKey";//
    else if(id == 0x00000051)    return "HvxGetUpdateSequence";//
    else if(id == 0x00000052)    return "HvxSecurityInitialize";//
    else if(id == 0x00000053)    return "HvxSecurityLoadSettings";//
    else if(id == 0x00000054)    return "HvxSecuritySaveSettings";//
    else if(id == 0x00000055)    return "HvxSecuritySetDetected";//
    else if(id == 0x00000056)    return "HvxSecurityGetDetected";//
    else if(id == 0x00000057)    return "HvxSecuritySetActivated";//
    else if(id == 0x00000058)    return "HvxSecurityGetActivated";//
    else if(id == 0x00000059)    return "HvxSecuritySetStat";//
    else if(id == 0x0000005A)    return "HvxGetProtectedFlags";//
    else if(id == 0x0000005B)    return "HvxSetProtectedFlag";//
    else if(id == 0x0000005C)    return "HvxDvdAuthGetAuthResults";//
    else if(id == 0x0000005D)    return "HvxDvdAuthSetDriveAuthResult";//
    else if(id == 0x0000005E)    return "HvxDvdAuthSetDiscAuthResult";//
    else if(id == 0x0000005F)    return "HvxImageTransformImageKey";//
    else if(id == 0x00000060)    return "HvxImageXexHeader";//
    else if(id == 0x00000061)    return "HvxRevokeLoad";//
    else if(id == 0x00000062)    return "HvxRevokeSave";//
    else if(id == 0x00000063)    return "HvxRevokeUpdate";//
    else if(id == 0x00000064)    return "HvxDvdAuthGetMediaId";//
    else if(id == 0x00000065)    return "HvxXexActivationGetNonce";//
    else if(id == 0x00000066)    return "HvxXexActivationSetLicense";//
    else if(id == 0x00000067)    return "HvxXexActivationVerifyOwnership";//
    else if(id == 0x00000068)    return "HvxIptvSetBoundaryKey";//
    else if(id == 0x00000069)    return "HvxIptvSetSessionKey";//
    else if(id == 0x0000006A)    return "HvxIptvVerifyOmac1Signature";//
    else if(id == 0x0000006B)    return "HvxIptvGetAesCtrTransform";//
    else if(id == 0x0000006C)    return "HvxIptvGetSessionKeyHash";//
    else if(id == 0x0000006D)    return "HvxImageDvdEmulationMode";
    else if(id == 0x0000006E)    return "HvxImageUserMode";
    else if(id == 0x0000006F)    return "HvxImageShim";//
    else if(id == 0x00000070)    return "HvxExpansionInstall";//
    else if(id == 0x00000071)    return "HvxExpansionCall";
    else if(id == 0x00000072)    return "HvxDvdAuthFwcr";//
    else if(id == 0x00000073)    return "HvxDvdAuthFcrt";//
    else if(id == 0x00000074)    return "HvxDvdAuthEx";//
    else if(id == 0x00000075)    return "HvxTest";
 
    else return form("HvxSyscall_%02X", id);
    /*if(        id == 0x00000000)    return "HvxGetVersions";
    else if(id == 0x00000001)    return "HvxStartupProcessors";
    else if(id == 0x00000002)    return "HvxQuiesceProcessor";
    else if(id == 0x00000003)    return "HvxFlushEntireTb";
    else if(id == 0x00000004)    return "HvxFlushSingleTb";
    else if(id == 0x00000005)    return "HvxRelocateAndFlush";
    else if(id == 0x00000006)    return "HvxGetSpecialPurposeRegister";
    else if(id == 0x00000007)    return "HvxSetSpecialPurposeRegister";
    else if(id == 0x00000008)    return "HvxGetSocRegister";
    else if(id == 0x00000009)    return "HvxSetSocRegister";
    else if(id == 0x0000000A)    return "HvxSetTimeBaseToZero";
    else if(id == 0x0000000B)    return "HvxZeroPage";
    else if(id == 0x0000000C)    return "HvxFlushDcacheRange";
    else if(id == 0x0000000D)    return "HvxPostOutput";
    else if(id == 0x0000000E)    return "HvxEnablePPUPerformanceMonitor";
    else if(id == 0x0000000F)    return "HvxGetImagePageTableEntry";
    else if(id == 0x00000010)    return "HvxSetImagePageTableEntry";
    else if(id == 0x00000011)    return "HvxCreateImageMapping";
    else if(id == 0x00000012)    return "HvxMapImagePage";
    else if(id == 0x00000013)    return "HvxCompleteImageMapping";
    else if(id == 0x00000014)    return "HvxLoadImageData";
    else if(id == 0x00000015)    return "HvxFinishImageDataLoad";
    else if(id == 0x00000016)    return "HvxStartResolveImports";
    else if(id == 0x00000017)    return "HvxResolveImports";
    else if(id == 0x00000018)    return "HvxFinishImageLoad";
    else if(id == 0x00000019)    return "HvxAbandonImageLoad";
    else if(id == 0x0000001A)    return "HvxUnmapImagePages";
    else if(id == 0x0000001B)    return "HvxUnmapImage";
    else if(id == 0x0000001C)    return "HvxUnmapImageRange";
    else if(id == 0x0000001D)    return "HvxCreateUserMode";
    else if(id == 0x0000001E)    return "HvxDeleteUserMode";
    else if(id == 0x0000001F)    return "HvxFlushUserModeTb";
    else if(id == 0x00000020)    return "HvxSetPowerMode";
    else if(id == 0x00000021)    return "HvxShadowBoot";
    else if(id == 0x00000022)    return "HvxBlowFuses";
    else if(id == 0x00000023)    return "HvxFsbInterrupt";
    else if(id == 0x00000024)    return "HvxLockL2";
    else if(id == 0x00000025)    return "HvxDvdAuthBuildNVPage";
    else if(id == 0x00000026)    return "HvxDvdAuthVerifyNVPage";
    else if(id == 0x00000027)    return "HvxDvdAuthRecordAuthenticationPage";
    else if(id == 0x00000028)    return "HvxDvdAuthRecordXControl";
    else if(id == 0x00000029)    return "HvxDvdAuthGetAuthPage";
    else if(id == 0x0000002A)    return "HvxDvdAuthVerifyAuthPage";
    else if(id == 0x0000002B)    return "HvxDvdAuthGetNextLBAIndex";
    else if(id == 0x0000002C)    return "HvxDvdAuthVerifyLBA";
    else if(id == 0x0000002D)    return "HvxDvdAuthClearDiscAuthInfo";
    else if(id == 0x0000002E)    return "HvxKeysInitialize";
    else if(id == 0x0000002F)    return "HvxKeysGetKeyProperties";
    else if(id == 0x00000030)    return "HvxKeysGetStatus";
    else if(id == 0x00000031)    return "HvxKeysGenerateRandomKey";
    else if(id == 0x00000032)    return "HvxKeysGetFactoryChallenge";
    else if(id == 0x00000033)    return "HvxKeysSetFactoryResponse";
    else if(id == 0x00000034)    return "HvxKeysSaveBootLoader";
    else if(id == 0x00000035)    return "HvxKeysSaveKeyVault";
    else if(id == 0x00000036)    return "HvxKeysSetKey";
    else if(id == 0x00000037)    return "HvxKeysGetKey";
    else if(id == 0x00000038)    return "HvxKeysGetDigest";
    else if(id == 0x00000039)    return "HvxKeysRsaPrvCrypt";
    else if(id == 0x0000003A)    return "HvxKeysHmacSha";
    else if(id == 0x0000003B)    return "HvxKeysAesCbc";
    else if(id == 0x0000003C)    return "HvxKeysDes2Cbc";
    else if(id == 0x0000003D)    return "HvxKeysDesCbc";
    else if(id == 0x0000003E)    return "HvxKeysObscureKey";
    else if(id == 0x0000003F)    return "HvxKeysSaveSystemUpdate";
    else if(id == 0x00000040)    return "HvxKeysExecute";
    else if(id == 0x00000041)    return "HvxDvdAuthTestMode";
    else if(id == 0x00000042)    return "HvxEnableTimebase";
    else if(id == 0x00000043)    return "HvxHdcpCalculateMi";
    else if(id == 0x00000044)    return "HvxHdcpCalculateAKsvSignature";
    else if(id == 0x00000045)    return "HvxHdcpCalculateBKsvSignature";
    else if(id == 0x00000046)    return "HvxSetRevocationList";
    else if(id == 0x00000047)    return "HvxEncryptedReserveAllocation";
    else if(id == 0x00000048)    return "HvxEncryptedReleaseAllocation";
    else if(id == 0x00000049)    return "HvxEncryptedEncryptAllocation";
    else if(id == 0x0000004A)    return "HvxEncryptedSweepAddressRange";
    else if(id == 0x0000004B)    return "HvxKeysExCreateKeyVault";
    else if(id == 0x0000004C)    return "HvxKeysExCreateKeyVault";
    else if(id == 0x0000004D)    return "HvxKeysExLoadKeyVault"; // "HvxKeysExSaveKeyVault"
    else if(id == 0x0000004E)    return "HvxKeysExSetKey";
    else if(id == 0x0000004F)    return "HvxKeysExGetKey";
    else if(id == 0x00000050)    return "HvxGetUpdateSequence";
    else if(id == 0x00000051)    return "HvxSecurityInitialize";
    else if(id == 0x00000052)    return "HvxSecurityLoadSettings";
    else if(id == 0x00000053)    return "HvxSecuritySaveSettings";
    else if(id == 0x00000054)    return "HvxSecuritySetDetected";
    else if(id == 0x00000055)    return "HvxSecurityGetDetected";
    else if(id == 0x00000056)    return "HvxSecuritySetActivated";
    else if(id == 0x00000057)    return "HvxSecurityGetActivated";
    else if(id == 0x00000058)    return "HvxSecuritySetStat";
    else if(id == 0x00000059)    return "HvxGetProtectedFlags";
    else if(id == 0x0000005A)    return "HvxSetProtectedFlag";
    else if(id == 0x0000005B)    return "HvxDvdAuthGetAuthResults";
    else if(id == 0x0000005C)    return "HvxDvdAuthSetDriveAuthResult";
    else if(id == 0x0000005D)    return "HvxDvdAuthSetDiscAuthResult";
    else if(id == 0x0000005E)    return "HvxImageTransformImageKey";
    else if(id == 0x0000005F)    return "HvxImageXexHeader";
    else if(id == 0x00000060)    return "HvxRevokeLoad";
    else if(id == 0x00000061)    return "HvxRevokeSave";
    else if(id == 0x00000062)    return "HvxRevokeUpdate";
    else if(id == 0x00000063)    return "HvxDvdAuthGetMediaId";
    else if(id == 0x00000064)    return "HvxKeysLoadKeyVault";
    else if(id == 0x00000065)    return "HvxXexActivationGetNonce";
    else if(id == 0x00000066)    return "HvxXexActivationSetLicense";
    else if(id == 0x00000067)    return "HvxXexActivationVerifyOwnership";
    else if(id == 0x00000068)    return "HvxIptvSetBoundaryKey";
    else if(id == 0x00000069)    return "HvxIptvSetSessionKey";
    else if(id == 0x0000006A)    return "HvxIptvVerifyOmac1Signature";
    else if(id == 0x0000006B)    return "HvxIptvGetAesCtrTransform";
    else if(id == 0x0000006C)    return "HvxIptvGetSessionKeyHash";
    else if(id == 0x0000006D)    return "HvxImageDvdEmulationMode";
    else if(id == 0x0000006E)    return "HvxImageUserMode";
    else if(id == 0x0000006F)    return "HvxImageShim";
    else if(id == 0x00000070)    return "HvxExpansionInstall";
    else if(id == 0x00000071)    return "HvxExpansionCall";
    else if(id == 0x00000072)    return "HvxDvdAuthFwcr";
    else if(id == 0x00000073)    return "HvxDvdAuthFcrt";
    else if(id == 0x00000074)    return "HvxDvdAuthEx";
    else if(id == 0x00000075)    return "HvxTest";
 
    else return form("HvxSyscall_%02X", id);*/
}
 
static SetupRegSaves()
{
    auto currAddr, i;
 
    // find all saves of gp regs
    for(currAddr=0; currAddr != BADADDR; currAddr=currAddr+4)
    {
        // find "std %r14, -0x98(%sp)" followed by "std %r15, -0x90(%sp)"
        currAddr = FindBinary(currAddr, SEARCH_DOWN, "F9 C1 FF 68 F9 E1 FF 70");
        if(currAddr == BADADDR)
            break;
        for(i=14; i<=31; i++)
        {
            MakeUnknown(currAddr, 8, 0); // DOUNK_SIMPLE 0 DOUNK_DELNAMES  0x0002
            MakeCode(currAddr);
            if(i != 31)
                MakeFunction(currAddr, currAddr + 4);
            else
                MakeFunction(currAddr, currAddr + 0x0C);
            if(MakeNameEx(currAddr, form("__Save_R12_%d_thru_31", i), SN_NOCHECK|SN_NOWARN) != 1)
                MakeNameEx(currAddr, form("__Save_R12_%d_thru_31_", i), 0);
            currAddr = currAddr + 4;
        }
    }
 
    // find all loads of gp regs
    for(currAddr=0; currAddr != BADADDR; currAddr=currAddr+4)
    {
        // find "ld  %r14, var_98(%sp)" followed by "ld  %r15, var_90(%sp)"
        currAddr = FindBinary(currAddr, SEARCH_DOWN, "E9 C1 FF 68 E9 E1 FF 70");
        if(currAddr == BADADDR)
            break;
        for(i=14; i<=31; i++)
        {
            MakeUnknown(currAddr, 8, 0); // DOUNK_SIMPLE
            MakeCode(currAddr);
            if(i != 31)
                MakeFunction(currAddr, currAddr + 4);
            else
                MakeFunction(currAddr, currAddr + 0x10);
            if(MakeNameEx(currAddr, form("__Rest_R12_lr_%d_thru_31", i), SN_NOCHECK|SN_NOWARN) != 1)
                MakeNameEx(currAddr, form("__Rest_R12_lr_%d_thru_31_", i), 0);
            currAddr = currAddr + 4;
        }
    }
}
 
static SetupSyscallTable()
{
    auto currAddr, sctable, scmax, i, scOff, str;
 
    Message(form("SystemCall reference to 0x%X found at 0x%X.\n", 0x15E60, 0xB28));
    // ROM:00000B28                addis    r4, r4, 1
    // ROM:00000B2C                addi      r4, r4, 0x5B70
    sctable = 0x15EC0;
    MakeNameEx(sctable, "_SyscallTable", 0);
 
    for(currAddr=0xB00; currAddr != BADADDR; currAddr=currAddr+4)
    {
        currAddr = FindBinary(currAddr, SEARCH_DOWN, "28 00 00");
        if(currAddr == BADADDR)
            break;
        if((currAddr & 0x3) == 0)
            break;
    }
    scmax = Byte(currAddr+3);
    MakeUnknown(sctable, scmax*4, DOUNK_DELNAMES);// DOUNK_SIMPLE 0 DOUNK_DELNAMES  0x0002
 
    for(i=0; i<scmax; i=i+1)
    {
        MakeDword(sctable+(4*i));
        scOff = Dword(sctable+(4*i));
        str = GetSyscallName(i);
        if((Dword(scOff) == 0x38600000) && (Dword(scOff+4) == 0x4E800020))
        {
            MakeRptCmt(sctable+(4*i), form("%s (disabled)", str));
        }
        else if((Word(scOff) == 0x3960) && (Word(scOff+4) == 0x4BFF)) // is a jumptable
        {
            MakeUnknown(scOff, 8, DOUNK_DELNAMES);
            MakeRptCmt(scOff, str);
        }
        else
        {
            MakeFunction(scOff, BADADDR);
            MakeNameEx(scOff, str, 0);
        }
    }
}
 
static SetupPointerBranches()
{
    auto currAddr, baseaddr, i, str, tabl;
    tabl = 1;
    for(currAddr = 0; currAddr != BADADDR; currAddr = currAddr + 4)
    {
        currAddr = FindBinary(currAddr, SEARCH_DOWN, "7D 8C 58 2E");
        if(currAddr == BADADDR)
            break;
        if((currAddr & 0x3) == 0)
        {
            currAddr = currAddr - 4;
            MakeFunction(currAddr, BADADDR);
            MakeName(currAddr, form("jt%d_jumper", tabl));
            baseaddr = 0xA590; 
            currAddr = 0xA7B4;
            i = 0;
            while(Word(currAddr) != 0)
            {
                str = CommentEx(currAddr, 1);
                if(strlen(str) != 0) // was commented previously, use the function name put there
                {
                    MakeNameEx(Dword(baseaddr+i), str, 0);
                    MakeRptCmt(currAddr, form("<- b 0x%X %s", Dword(baseaddr+i), str));
                    MakeNameEx(currAddr, form("jt%d_%s", tabl, str), 0);
                }
                else
                    MakeRptCmt(currAddr, form("<- b 0x%X", Dword(baseaddr+i)));
                MakeFunction(currAddr, BADADDR);
                MakeFunction(Dword(baseaddr+i), BADADDR);
                 
                currAddr = currAddr + 8;
                i = i+4;
            }
            break;
        }
    }
}
 
static RemoveAllChunks(address)
{
    auto a, b;
    a = NextFuncFchunk(address, address);
    b=0;
    while(a != BADADDR)
    {
        RemoveFchunk(address, a);
        a = NextFuncFchunk(address, address);
        b = b +1;
    }
    Message(form("function at 0x%08X, removed %d chunks\n",address,b));
}
 
static CreateVector(address, name)
{
    auto a, b;
    MakeName(address, name);
    MakeFunction(address, BADADDR);
}
 
static SetupVectors()
{
    CreateVector(0x00000100, "_v_RESET");
    CreateVector(0x00000200, "_v_MACHINE_CHECK");
    CreateVector(0x00000218, "_v_MACHINE_CHECK_0");
    CreateVector(0x00000300, "_v_DATA_STORAGE");
    CreateVector(0x00000380, "_v_DATA_SEGMENT");
    CreateVector(0x00000400, "_v_INSTRUCTION_STORAGE");
    CreateVector(0x00000480, "_v_INSTRUCTION_SEGMENT");
    CreateVector(0x00000500, "_v_EXTERNAL");
    CreateVector(0x00000600, "_v_ALIGNMENT");
    CreateVector(0x00000700, "_v_PROGRAM");
    CreateVector(0x00000800, "_v_FPU_UNAVAILABLE");
    CreateVector(0x00000900, "_v_DECREMENTER");
    CreateVector(0x00000980, "_v_HYPERVISOR_DECREMENTER");
    CreateVector(0x00000B9C, "_v_Reserved_B9C");
    CreateVector(0x00000C00, "_v_SYSTEM_CALL");
    CreateVector(0x00000D00, "_v_TRACE");
    CreateVector(0x00000A5C, "_v_FPU_Assist");
    CreateVector(0x00000F20, "_v_VPU_UNAVAILABLE");
    CreateVector(0x00001600, "_v_MAINTENANCE");
    CreateVector(0x00001700, "_v_VMX_ASSIST");
    CreateVector(0x00001800, "_v_THERMAL_MANAGEMENT");
}
 
static SetupVariousFunctions()
{
    CreateVector(0x00023F8C, "XeCryptAesEncrypt");
    CreateVector(0x00020108, "XeCryptAesEcb");
    CreateVector(0x000241D4, "XeCryptAesDecrypt");
    CreateVector(0x00020128, "XeCryptAesCbc");
    CreateVector(0x00023DD0, "XeCryptAesKeyTable");
    CreateVector(0x00020300, "XeCryptAesCbcMac");
    CreateVector(0x00023500, "XeCryptMemDiff");
    CreateVector(0x000226F0, "XeCryptShaInit");
    CreateVector(0x00022738, "XeCryptShaTransform");
    CreateVector(0x00020520, "XeCryptBnDw_Copy");
    CreateVector(0x00009F90, "memcpy");
    CreateVector(0x0000A430, "memset");
    CreateVector(0x00022DB8, "XeCryptSha");
    CreateVector(0x00022BD0, "XeCryptShaUpdate");
    CreateVector(0x00022CF0, "XeCryptShaFinal");
    CreateVector(0x00023170, "XeCryptRc4Key");
    CreateVector(0x00023218, "XeCryptRc4Ecb");
    CreateVector(0x00020578, "XeCryptBnQwBeSigFormat");
    CreateVector(0x00020F00, "XeCryptBnQwNeModMul");
    CreateVector(0x00021210, "XeCryptBnQw_Copy");
    CreateVector(0x00020EC8, "XeCryptBnQwNeModInv");
    CreateVector(0x000244D8, "XeCryptBnQwNeDigLen");
    CreateVector(0x00024560, "XeCryptBnQwNeMul");
    CreateVector(0x000211F0, "XeCryptBnQw_Zero");
    CreateVector(0x00024AF0, "XeCryptBnQwNeAcc");
    CreateVector(0x00024A40, "XeCryptBnQwNeAdd");
    CreateVector(0x00024A98, "XeCryptBnQwNeSub");
    CreateVector(0x000247D0, "XeCryptBnQwNeMod");
    CreateVector(0x00020910, "XeCryptBnQwNeModExp");
    CreateVector(0x00024C68, "XeCryptBnQwNeCompare");
    CreateVector(0x00023108, "XeCryptRc4");
    CreateVector(0x00022E98, "XeCryptHmacShaInit");
    CreateVector(0x00023010, "XeCryptHmacShaFinal");
    CreateVector(0x00023060, "XeCryptHmacSha"); 
    CreateVector(0x000200F8, "XeCryptAesKey");
    CreateVector(0x00023008, "XeCryptHmacShaUpdate");
    CreateVector(0x00021128, "XeCryptBnQwNeRsaPubCrypt");
    CreateVector(0x00020D28, "XeCryptBnQwNeModExpRoot");
    CreateVector(0x000211A8, "XeCryptBnQwNeRsaPrvCrypt");
    CreateVector(0x00021240, "XeCryptBnQw_SwapDwQwLeBe");
    CreateVector(0x00021840, "XeCryptDes3Cbc");
    CreateVector(0x00021BC8, "XeCryptDes3Key");
    CreateVector(0x000217C0, "XeCryptDes3Ecb");
    CreateVector(0x00021968, "XeCryptDesKey");
    CreateVector(0x00021710, "XeCryptDesCbc");
    CreateVector(0x00021270, "XeCryptDesEcb");
    CreateVector(0x00021C08, "XeCryptDesParity");
    CreateVector(0x00023278, "XeCryptRotSum");
    CreateVector(0x00023330, "XeCryptRotSumSha");
    CreateVector(0x00020550, "XeCryptBnDw_SwapLeBe");
    CreateVector(0x00020250, "XeCryptAesCtr");
    CreateVector(0x00020468, "XeCryptBnDwLePkcs1Verify");
    CreateVector(0x000203A8, "XeCryptBnDwLePkcs1Format");
    CreateVector(0x00024420, "XeCryptBnQwBeSigDifference");
    CreateVector(0x00020680, "XeCryptBnQwBeSigVerify");
    CreateVector(0x00000E14, "HvpRelocateCacheLines"); // thanks to cory1492 @ XBH
}
 
static SetupXeKeyTables()
{
    /* 
    Key Properties : Total Size = Dword
            @h 16 bits : Unknown
            @l 16 bits : Key Size
    thanks to ANTMAN @ XBH
    */
    auto i, addr;
    addr = 0x10B70;
    MakeName(addr, "_XeKeys_Properties_Table");
    MakeComm(0x4A50, "Key Table @ 0x10B70");
    for (i = 0; i < 0x39; i++) // keys 0x0 - 0x38
    {
        MakeDword(addr + (i*4));
        OpHex(addr + (i*4),-1);
    }
    addr = 0x10C70;
    MakeName(addr, "_XeKeys_Properties_Table_2");
    MakeComm(0x4A60, "XeKeys 0x100 - 0x10D");
    MakeComm(0x4A78, "Key Table @ 0x10C70");
    for(i = 0; i < 0xE; i++) // keys 0x100 - 0x10D
    {
        MakeDword(addr + (i*4));
        OpHex(addr + (i*4),-1);     
    }
    Message("Done with KeyTables\n");
}
 
static main()
{
    SetPrcsr("PPC");
    SetCharPrm(INF_COMPILER, COMP_MS);
    //SetCharPrm(INF_GENFLAGS, INFFL_LZERO); // Show leading zero's
    SetCharPrm(INF_MODEL, 0x33); // should be calling conv cdecl, memory model "code near,data near" - use GetCharPerm(INF_MODEL) with right settings to find out val if this is wrong
    SetShortPrm(INF_AF2, ~AF2_FTAIL&GetShortPrm(INF_AF2)); // turns off creating function chunk tails
 
    SetupSyscallTable();
    SetupVariousFunctions();
    SetupPointerBranches();
    SetupVectors();
    SetupRegSaves();
    SetupXeKeyTables();
 
    SetShortPrm(INF_AF2, ~AF2_FTAIL&GetShortPrm(INF_AF2)); // turns on creating function chunk tails
    Message("done!\n\n");
}