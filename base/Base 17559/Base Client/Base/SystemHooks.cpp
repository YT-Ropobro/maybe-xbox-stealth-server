#include "stdafx.h"

int msgDisplayed = 0;
extern BYTE cpuKeyDigest[];
BYTE kvBytes[0x4000];
extern BYTE kvDigest[];
extern KEY_VAULT keyVault;
extern BYTE hvRandomData[];
extern BYTE seshKey[];
extern BYTE cpuKeySpoofedHash[XECRYPT_SHA_DIGEST_SIZE];
extern HANDLE hXBLAcroze;
extern BOOL IsDevkit;
extern DWORD dwUpdateSequence;
extern BOOL crl;
extern BOOL fcrt;
extern HANDLE hXBLS;
extern BOOL type1KV;
extern BOOL XBLSInitialized;
extern wchar_t challengeNotify[XSTL_BUFFER_CHALLENGENOTIFYLEN];
bool didnotify = false;
MESSAGEBOX_RESULT result;
XOVERLAPPED overlapped;
// Static execution id for titles that don't have one
XEX_EXECUTION_ID xeExecutionIdSpoof;
XEX_EXECUTION_ID XamLoaderID;
BYTE XeKeysCPU[0x10];
BYTE Hash[0xEC];
BYTE HvDigest[0x6];
BYTE Membo[0x14];
BYTE eccAR[0x13];
BYTE bSalt[0x14];
BYTE ECC[0x2];
BYTE Flags[2] = { 0x07, 0x60 };
BYTE RandomData[0x80];
BYTE HVEXADDR[2] = { 0x01, 0xB5 };
BYTE PDRFlags[] = { 0x45, 0x64, 0x69, 0x74, 0x65, 0x64, 0x20, 0x26, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x53, 0x69, 0x6c, 0x65, 0x6e, 0x74 };
BYTE Shitheads[] = { 0x44 , 0x65, 0x6d, 0x6f, 0x6e, 0x20, 0x46, 0x6f, 0x72, 0x75, 0x6d, 0x73, 0x2c, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x61, 0x72, 0x65, 0x20, 0x77, 0x65, 0x6c, 0x63, 0x6f, 0x6d, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x76, 0x69, 0x64, 0x65, 0x6f, 0x73, 0x21 };
BYTE MoreSheads[] = { 0x6d, 0x69, 0x64, 0x64, 0x6c, 0x65, 0x20, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x20, 0x75, 0x70, 0x3a, 0x20, 0x78, 0x62, 0x6f, 0x78, 0x20, 0x6b, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2c, 0x20, 0x67, 0x69, 0x74, 0x68, 0x73, 0x2c, 0x20, 0x4d, 0x72, 0x2e, 0x46, 0x75, 0x7a, 0x79, 0x2c, 0x20, 0x6b, 0x79, 0x75, 0x62, 0x69, 0x69, 0x2c, 0x20, 0x26, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x64, 0x69, 0x72, 0x74, 0x62, 0x61, 0x67, 0x73, 0x20, 0x77, 0x68, 0x6f, 0x20, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x73, 0x74, 0x75, 0x66, 0x66, 0x20, 0x26, 0x20, 0x68, 0x61, 0x6c, 0x66, 0x2d, 0x61, 0x73, 0x73, 0x20, 0x65, 0x78, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x66, 0x6f, 0x72, 0x67, 0x65, 0x74, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x77, 0x65, 0x72, 0x65, 0x20, 0x6f, 0x6e, 0x63, 0x65, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x74, 0x6f, 0x2e, 0x20, 0x53, 0x6f, 0x6d, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x75, 0x73, 0x20, 0x77, 0x69, 0x6c, 0x6c, 0x20, 0x68, 0x65, 0x6c, 0x70, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x70, 0x65, 0x6f, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x75, 0x74 };
BYTE EvenmoreShitheads[] = { 0x69, 0x20, 0x6b, 0x6e, 0x6f, 0x77, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x20, 0x64, 0x69, 0x72, 0x74, 0x62, 0x61, 0x67, 0x73, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x72, 0x65, 0x61, 0x64, 0x20, 0x74, 0x68, 0x69, 0x73, 0x2e, 0x20, 0x66, 0x75, 0x63, 0x6b, 0x20, 0x6f, 0x66, 0x66, 0x21, 0x21 };
EXTERN_C  DWORD ExecuteSpoofedSupervisorChallenge(DWORD dwTaskParam1, BYTE* pbDaeTableName, DWORD cbDaeTableName, BYTE* pBuffer, DWORD cbBuffer) {
	return CreateXOSCBuffer(dwTaskParam1, pbDaeTableName, cbDaeTableName, (XOSC*)pBuffer, cbBuffer);
}

typedef DWORD(*XEKEYSEXECUTE)(BYTE* chalData, DWORD size, BYTE* HVSalt, UINT64 krnlBuild, UINT64 r7, UINT64 r8);
HRESULT DoRandomData() {
	return HvPeekBytes(0x0000000200010040, hvRandomData, 0x80) == 0 ? ERROR_SUCCESS : E_FAIL;
}
QWORD SpoofXamChallenge(BYTE* pBuffer, DWORD dwFileSize, BYTE* Salt, QWORD Input2, QWORD Input3, QWORD Input4) {

	// Make sure we are even good to go first
	while (!XBLSInitialized) { Sleep(1); }

	// Setup some variables
	SERVER_CHAL_REQUEST   chalRequest;
	SERVER_CHAL_RESPONCE* pChalResponce = (SERVER_CHAL_RESPONCE*)pBuffer;

	// Setup our request
	memcpy(chalRequest.SessionKey, seshKey, 16);
	memcpy(chalRequest.Salt, Salt, 16);
	chalRequest.Crl = crl;
	chalRequest.Fcrt = fcrt;
	chalRequest.Type1Kv = type1KV;

	// Send our request and recieve our responce
	if (SendCommand(XSTL_SERVER_COMMAND_ID_GET_CHAL_RESPONCE, &chalRequest, sizeof(SERVER_CHAL_REQUEST), pChalResponce, sizeof(SERVER_CHAL_RESPONCE)) != ERROR_SUCCESS) {
		DbgPrint("SpoofXamChallenge - SendCommand Failed");
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return 0;
	}

	// Check our responce
	if (pChalResponce->Status != XSTL_STATUS_SUCCESS && pChalResponce->Status != XSTL_STATUS_STEALTHED) {
		DbgPrint("SpoofXamChallenge - Bad status");
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return 0;
	}

	// Now we can clear our result and fix any other variables
	pChalResponce->Status = 0;
	XAM_CHAL_RESP* pXamChalResp = (XAM_CHAL_RESP*)(pBuffer + 0x20);
	pXamChalResp->dwUpdateSequence = dwUpdateSequence;
	memcpy(pXamChalResp->bCpuKeyDigest, cpuKeyDigest, XECRYPT_SHA_DIGEST_SIZE);
	//memcpy(pXamChalResp->bRandomData, hvRandomData, 0x80);
	//Fixes Paid for  15/02/2016

	DoRandomData();//Get Random Data from Current HV
	BYTE Flags[2] = { 0x07, 0x60 };
	BYTE HVEXADDR[2] = { 0x01, 0xB5 };
	memset(pBuffer + 0x100, 0, 0xF00);//Clear all random junk from buffer
	memcpy(pBuffer + 0x2E, pBuffer + 0x30, 2); //Copy our BLDR Flags from Original Postion @ 0x30, to 0x2E
	memcpy(pBuffer + 0x30, Flags, 2);//Copy Correct Flags for 0x30 (Static)
	memcpy(pBuffer + 0x78, hvRandomData, 0x80);//Copy Correct HV Random Data
	memcpy(pBuffer + 0xF8, HVEXADDR, 2); //Copy our HVEXAddress (Static for now, how da fuq do they even check that)


	crl = TRUE;
	if (!didnotify) { XNotifyUI(challengeNotify); didnotify = true; }
	CWriteFile("HDD:\\MyChallengeDump.bin", pBuffer, dwFileSize);
	return 0;
}

QWORD XeKeysExecuteHook(VOID* pBuffer, DWORD dwFileSize, QWORD Input1, QWORD Input2, QWORD Input3, QWORD Input4)
{
	return SpoofXamChallenge((BYTE*)pBuffer, dwFileSize, (BYTE*)Input1, Input2, Input3, Input4);
}

DWORD XexLoadImageFromMemoryHook(VOID* Image, DWORD ImageSize, const CHAR* ImageName, DWORD LoadFlags, DWORD Version, HMODULE* ModuleHandle) {

	if (memcmp(ImageName, "xosc", 4) == 0) {
		*ModuleHandle = (HMODULE)hXBLS;
		return 0;
	}
	return XexLoadImageFromMemory(Image, ImageSize, ImageName, LoadFlags, Version, (PHANDLE)ModuleHandle);
}
VOID* RtlImageXexHeaderFieldHook(VOID* headerBase, DWORD imageKey)
{
	// Call it like normal
	VOID* retVal = RtlImageXexHeaderField(headerBase, imageKey);

	// See if we are looking for our Execution ID and if its found lets patch it if we must
	if (imageKey == 0x40006 && retVal)
	{
		switch (((XEX_EXECUTION_ID*)retVal)->TitleID)
		{
		case 0xFFFF0055: // Xex Menu
		case 0xC0DE9999: // Xex Menu alt
		case 0xFFFE07FF: // XShellXDK
		case 0xF5D20000: // FSD
		case 0xFFFF011D: // DashLaunch
		{
			SetMemory(retVal, &xeExecutionIdSpoof, sizeof(XEX_EXECUTION_ID));
			break;
		}
		}
	}
	else if (imageKey == 0x40006 && !retVal)
	{
		// We couldn't find an execution id so lets return ours
		retVal = &xeExecutionIdSpoof;
	}

	// Return like normal
	return retVal;
}
NTSTATUS XexLoadImageHook(LPCSTR szXexName, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion, PHANDLE pHandle)
{
	// Call our load function with our own handle pointer, just in case the original is kvb
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
	// Call our load function with our own handle pointer, just in case the original is null
	HANDLE mHandle = NULL;
	NTSTATUS result = XexLoadExecutable(szXexName, &mHandle, dwModuleTypeFlags, dwMinimumVersion);
	if (pHandle != NULL) *pHandle = mHandle;
	// If successesful, let's do our patches, passing our handle
	if (NT_SUCCESS(result)) InitializeTitleSpecificHooks((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle);
	// All done
	return result;
}
DWORD ReadKV() // call this
{
	QWORD kvAddress = HvPeekQWORD(0x0000000200016240);
	HvPeekBytes(kvAddress, &kvBytes, 0x4000);
	return ERROR_SUCCESS;
}
typedef DWORD(*ExecuteSupervisorChallenge_t)(DWORD dwTaskParam1, PBYTE pbDaeTableName, DWORD cbDaeTableName, PBYTE pbBuffer, DWORD cbBuffer);
DWORD XamLoaderExecuteAsyncChallengeHook(DWORD Address, DWORD Task, PBYTE DaeTableHash, DWORD DaeTableSize, PBYTE Buffer, DWORD Length, pXOSC resp, LPVOID pCommandBuffer, LPVOID pRecvBuffer, BYTE Index, INT Fan, INT Speed, BYTE Command, BOOL Animate, DWORD dwTaskParam1, BYTE* pbDaeTableName, DWORD cbDaeTableName, XOSC* pBuffer, DWORD cbBuffer) {
	//Definitions
	BYTE DriveData[0x24];
	BYTE console_serial[0xC];
	BYTE KvSerialNumber[0xC];
	BYTE SEC_FUSES[0x10];
	BYTE KvConsoleID[5];
	BYTE console_id[0x5];
	BYTE KvHash[0x10];
	BYTE xam_odd;
	BYTE KvDrivePhaseLevel;
	BYTE drive_phase_level;
	BYTE xam_region;
	//Clean HV
	//ExecuteHV();
	ZeroMemory((PVOID)(0x8E038780), 0x14);
	MemoryBuffer pbKV;
	BYTE kvBytes[0x4000];
	WORD BldrFlags = 0xD81E, BldrFlags1 = (~0x20);
	DWORD HvStatusFlags = 0x23289D3, result;
	//KVStatus();
	//XOSCBuffer(dwTaskParam1, pbDaeTableName, cbDaeTableName, pBuffer, cbBuffer);
	BYTE* KeyVault = (BYTE*)malloc(0x4000);
	QWORD kvAddress = HvPeekQWORD(0x0000000200016240);
	HvPeekBytes(kvAddress, KeyVault, 0x4000);

	HvStatusFlags = (crl == 1 || crl == TRUE) ? (HvStatusFlags | 0x10000) : HvStatusFlags; HvStatusFlags = (fcrt == 1 || fcrt == TRUE) ? (HvStatusFlags | 0x1000000) : HvStatusFlags;
	BldrFlags = (type1KV == 1 || type1KV == TRUE) ? ((WORD)(BldrFlags & BldrFlags1)) : BldrFlags;

	if (XamLoaderIsTitleTerminatePending()) resp->qwOperations |= 0x4000000000000000;
	if (XamTaskShouldExit()) resp->qwOperations |= 0x2000000000000000;
	//CReadFile(RunningFromUSB ? "Usb:\\KV.bin" : "Hdd:\\KV.bin", pbKV);
	memcpy(kvBytes, pbKV.GetData(), 0x4000);
	PBYTE KvFile = pbKV.GetData();

	memset((BYTE*)0x8E038780, 0, 0x14);

	unsigned short BLDRFlags = 0xD83E, BLDR_FLAGS_KV1 = (~0x20);
	unsigned int HvKeysStatusFlag = 0x23289D3;

	if (type1KV) { BLDRFlags = (unsigned short)(BLDRFlags & BLDR_FLAGS_KV1); }
	//HV Definitions
	HvKeysStatusFlag = (crl) ? (HvKeysStatusFlag | 0x10000) : HvKeysStatusFlag;
	HvKeysStatusFlag = (fcrt) ? (HvKeysStatusFlag | 0x1000000) : HvKeysStatusFlag;
	BLDRFlags = (type1KV == 1) ? ((WORD)(BLDRFlags & BLDR_FLAGS_KV1)) : BLDRFlags;
	QWORD HVProtectedFlags = *((PQWORD)0x8E038678);
	QWORD FinalHVProtectedFlags = 1;
	int XOSC_FLAG_BASE = 0x2bf;
	int HV_PROTECTED_FLAGS_NONE = 0;
	int HV_PROTECTED_FLAGS_NO_EJECT_REBOOT = 1;
	int HV_PROTECTED_FLAGS_AUTH_EX_CAP = 4;
	QWORD HV_PROTECTED_FLAGS = HV_PROTECTED_FLAGS_AUTH_EX_CAP | (((HVProtectedFlags & HV_PROTECTED_FLAGS_NO_EJECT_REBOOT) == HV_PROTECTED_FLAGS_NO_EJECT_REBOOT) ? HV_PROTECTED_FLAGS_NO_EJECT_REBOOT : HV_PROTECTED_FLAGS_NONE);

	if (HVProtectedFlags == 0)
		FinalHVProtectedFlags = 2;
	//Execute our console type command and patch Bytes
	//DWORD SpoofedHardFlag = SMC::HardwareInfoSpoof() | 0x227;
	//*(DWORD*)(Buffer + 0x1D0) = SpoofedHardFlag;
	//SMC::AllSMC(pCommandBuffer, pRecvBuffer, Color, Index, Fan, Speed, sTopLeft, sTopRight, sBottomLeft, sBottomRight, Command, Animate);


	//XNotifyQueueUI(XNOTIFYUI_TYPE_COMPLAINT, 0, 2, L"Silent - Gold Spoofed, KV Unbanned, & Connected to Live!", NULL);
	// Fixed bytes//17526
	//*(DWORD*)(0x8167F8D8) = 0x5563DFFE; // Gold Spoof
	//*(DWORD*)(0x81A3BCB8) = 0x5563673E; // Gold Bar

	//New Stuff 3.7.2019
	//Offsets for fuses
	//memcpy(pbBuffer + 0x10, kvDigest, 0x10); // kv hash digest
	//memcpy(pbBuffer + 0x50, cpuKeyDigest, 0x10); // cpu digest
	memcpy(Buffer + 0x70, (void*)0x8E03AA50, 0x10); // fuses
	memcpy(Buffer + 0x60, (void*)0x8E03AA40, 0x10); // fuses
	memcpy(Buffer + 0x50, (void*)0x8E03AA30, 0x10); // fuses i think cpufuse

													//KV Spoofing
	drive_phase_level = *(BYTE*)(KvFile + 0xc89);
	memcpy(DriveData, KvFile + 0xC8A, 0x24);
	xam_region = *(WORD*)(KvFile + 0xC8);
	xam_odd = *(WORD*)(KvFile + 0x1C);
	memcpy(DriveData, KvFile + 0xc8a, 0x24);
	memcpy(console_id, KvFile + 0x9CA, 5);
	memcpy(console_serial, KvFile + 0xB0, 12);

	//Console + Xam Spoofing
	*(BYTE*)(Buffer + 0x83) = drive_phase_level;
	memcpy(Buffer + 0xF0, DriveData, 36);
	memcpy(Buffer + 0x114, DriveData, 36);
	memcpy(Buffer + 0x138, console_serial, 12);
	*(WORD*)(Buffer + 0x146) = BLDRFlags;
	*(WORD*)(Buffer + 0x148) = xam_region;
	*(WORD*)(Buffer + 0x14A) = xam_odd;
	memcpy(Buffer + 0x1A0, console_id, 0x5);
	memcpy(Buffer + 0x70, SEC_FUSES, 0x10);

	// HV + Flag Spoofing
	BYTE * XoscBuff = (BYTE*)malloc(0x2E0);
	memset(XoscBuff, 0, 0x2e0);
	*(DWORD*)(XoscBuff + 0x04) = 0x90002;
	*(QWORD*)(XoscBuff + 0x08) = XOSC_FLAG_BASE;
	*(DWORD*)(XoscBuff + 0x20) = 0xC8003003;
	memset(XoscBuff + 0x24, 0xAA, 0x10);
	*(QWORD*)(XoscBuff + 0x70) = 0x527A5A4BD8F505BB;
	*(QWORD*)(XoscBuff + 0x78) = 0x94305A1779729F3B;
	*(DWORD*)(XoscBuff + 0x158) = HvKeysStatusFlag;
	memset(XoscBuff + 0x15C, 0xAA, 0x4);
	memset(XoscBuff + 0x16C, 0xAA, 0x4);
	*(DWORD*)(XoscBuff + 0x170) = 0xD0008;

	// Console + HV Flag Spoofing
	*(WORD*)(XoscBuff + 0x176) = 8;
	*(QWORD*)(XoscBuff + 0x198) = HV_PROTECTED_FLAGS;
	memcpy((XoscBuff + 0x1A0), console_id, 0x5);
	*(DWORD*)(XoscBuff + 0x1D0) = 0x40000207;
	memset(XoscBuff + 0x21C, 0xAA, 0xA4);
	*(WORD*)(XoscBuff + 0x2B8) = 0x20;
	*(WORD*)(XoscBuff + 0x2C6) = 0x6;
	memset(XoscBuff + 0x2C8, 0xAA, 0x10);
	*(DWORD*)(XoscBuff + 0x2D8) = 0x5F534750;
	memset(XoscBuff + 0x2DC, 0xAA, 4);

	//Execution Game Spoofing - Disables game check
	XEX_EXECUTION_ID* exeId;
	DWORD ExeResult = XamGetExecutionId(&exeId);
	BYTE * exeID = (BYTE*)malloc(0x18);
	*(DWORD*)exeID = exeId->MediaID;
	*(DWORD*)(exeID + 4) = exeId->Version;
	*(DWORD*)(exeID + 8) = exeId->BaseVersion;
	*(DWORD*)(exeID + 12) = exeId->TitleID;
	*(BYTE*)(exeID + 16) = exeId->Platform;
	*(BYTE*)(exeID + 17) = exeId->ExecutableType;
	*(BYTE*)(exeID + 18) = exeId->Platform;
	*(BYTE*)(exeID + 19) = exeId->ExecutableType;
	*(DWORD*)(exeID + 20) = exeId->SaveGameID;
	if (ExeResult == 0) {
		memcpy(XoscBuff + 0x38, exeID, 0x18);
		memset(XoscBuff + 0x84, 0, 0x8);
	}
	else
	{
		memset(XoscBuff + 0x38, 0xAA, 0x18);//not sure on this
		memset(XoscBuff + 0x84, 0xAA, 8);
		XOSC_FLAG_BASE &= -5;
		*(QWORD*)(XoscBuff + 8) = XOSC_FLAG_BASE;
	}
	*(DWORD*)(XoscBuff + 0x18) = ExeResult;
	///////////////////end of new shit///////////////////////////////////////////

	ZeroMemory(Buffer, Length);
	((VOID(*)(DWORD, PBYTE, DWORD, PBYTE, DWORD))Address)(Task, DaeTableHash, DaeTableSize, Buffer, Length);

	*(PDWORD)(Buffer + 0x10) = 0x00000000;
	*(PDWORD)(Buffer + 0x34) = 0x40000012;
	//memcpy(Buffer + 0x38, CleanExecutionId, 0x18);
	memcpy(Buffer + 0x50, cpuKeyDigest, 0x10);
	//memcpy(Buffer + 0x70, ValidDigest, 0x10);
	memcpy(Buffer + 0xF0, kvBytes + 0xC89, 0x24);
	memcpy(Buffer + 0x114, kvBytes + 0xC8A, 0x24);
	memcpy(Buffer + 0x138, kvBytes + 0xB0, 0x0C);
	*(PBYTE)(Buffer + 0x145) = 0xAA;
	*(PWORD)(Buffer + 0x146) = (type1KV) ? 0xD81E : 0xD83E;
	memcpy(Buffer + 0x148, kvBytes + 0xC8, 0x02);
	memcpy(Buffer + 0x14A, kvBytes + 0x1C, 0x02);
	*(PDWORD)(Buffer + 0x150) = 0xFFFFFFFF;
	memcpy(Buffer + 0x1A0, kvBytes + 0x9CA, 0x05);
	*(PDWORD)(Buffer + 0x1D0) = XboxHardwareInfo->Flags;
	KEY_VAULT keyVault;
	memcpy(Buffer + 0x198, &FinalHVProtectedFlags, 0x08);
	memcpy(Buffer + 0x38, &xeExecutionIdSpoof, sizeof(XEX_EXECUTION_ID));
	*(PDWORD)(Buffer + 0x44) = DASHBOARD;
	memcpy(Buffer + 0xF0, kvBytes + 0xC8A, 0x24);		//KvDriveData1
	memcpy(Buffer + 0x114, kvBytes + 0xC8A, 0x24);	//KvDriveData2
	*(PDWORD)(Buffer + 0x150) = keyVault.PolicyFlashSize; // PolicyFlashSize
	memcpy(Buffer + 0x138, kvBytes + 0xB0, 0xC);		//seriel
	memcpy(Buffer + 0x83, kvBytes + 0xC89, 0x01);		//Phase Level
	memcpy(Buffer + 0x148, kvBytes + 0xC8, 0x02);		//Xam Region
	memcpy(Buffer + 0x14A, kvBytes + 0x1C, 0x02);		//Xam ODD
	memcpy(Buffer + 0x1A0, kvBytes + 0x9CA, 0x05);	//Console ID
	*(PDWORD)(Buffer + 0x2DC) = 0x5F534750;
	*(PDWORD)(Buffer + 0x3C) = 0x2040A300;
	*(PDWORD)(Buffer + 0x154) = 0x070000;
	*(PQWORD)(Buffer + 0x70) = 0x527A5A4BD8F505BB; // fuses sec key
	memcpy(Buffer + 0x198, &FinalHVProtectedFlags, 0x08);
	memcpy(Buffer + 0x146, &BLDRFlags, 0x02); // correct our   BLDRFlags
	memcpy(Buffer + 0x158, &HvKeysStatusFlag, 0x04); // correct our  HvKeysStatusFlags
	 // Anti Piracy Flags
	*(INT*)(0x9001639C) = 0x39200001;
	*(INT*)(0x900163B4) = 0x39400001;
	*(INT*)(0x900163C4) = 0x38C00020;
	*(INT*)(0x900161D4) = 0x3900FFFF;
	*(INT*)(0x90016414) = 0x3900FFFF;
	*(INT*)(0x900162BC) = 0x38C00008;
	*(INT*)(0x9001516C) = 0x39200000;
	// Xam Patches // 
	*(DWORD*)(0x81682544) = 0x60000000; //nop EvaluateContent Serial Check 4x //old  816825F4
	*(DWORD*)(0x816798EC) = 0x60000000; //nop MmGetPhysicalAddress For Challenge 1 //old 8167999C
	*(DWORD*)(0x8167F978) = 0x38600000; //XContent::ContentEvaluateLicense 3  8167FA28old
	*(DWORD*)(0x8167C4B4) = 0x38600000; //XeKeysVerifyRSASignature 2 8167C564 old
	*(DWORD*)(0x8192DF78) = 0x60000000; //ProfileEmbeddedContent::Validate remove sig 8192D798 old 
	//Gold Spoof 
	*(DWORD*)(0x816DAC84) = 0x38600006;//XamUserGetMembershipTier old 816DAE24
	*(DWORD*)(0x81A3CD60) = 0x38600001;// 81A3BEC0 old
	*(DWORD*)(0x816DD688) = 0x39600001;//XamUserCheckPrivilege 816DD968 old need to check
	*(DWORD*)(0x816DD694) = 0x39600001;// 816DD974 old 
	*(DWORD*)(0x816DD6F4) = 0x39600001;// 816DD9D4 old 
	*(DWORD*)(0x816DD6E8) = 0x39600001;// 816DD9C8 old 
	DWORD li = 0x38600001;
	li += 5;
	SetMemory((LPVOID)(0x816DAC48 + 0x34), &li, 4);// 816DADE8 old .globl XamUserGetMembershipTier
	SetMemory((LPVOID)(0x816DACA8 + 0x38), &li, 4);//  816DAE48 old .globl XamUserGetMembershipTierFromXUID
	RtlLeaveCriticalSection((PRTL_CRITICAL_SECTION)(PDWORD)(0x81A9F858));
	//SMC::HalSendSMCMessageHook;//added 3/7/2019
	return S_OK;
}

BOOL XexCheckExecutablePrivilegeHook(DWORD priv) {

	// Allow insecure sockets for all titles
	if (priv == 6)
		return TRUE;

	return XexCheckExecutablePrivilege(priv);
}

void patchXamQosHang() {
	if (IsDevkit) { //17349 for devkits only!
		DWORD nop = 0x60000000;
		SetMemory((PVOID)0x8189B160, &nop, sizeof(DWORD));
		SetMemory((PVOID)0x8189B058, &nop, sizeof(DWORD));
	}
}
VOID __declspec(naked) NetDll_XnpSaveMachineAccountSaveVar(VOID)
{
	__asm
	{
		li r3, 745
		nop
		nop
		nop
		nop
		nop
		nop
		blr
	}
}

typedef HRESULT(*pNetDll_XnpSaveMachineAccount)(DWORD xamDebugLvl, PBYTE machineAcct);
//pNetDll_XnpSaveMachineAccount NetDll_XnpSaveMachineAccount = (pNetDll_XnpSaveMachineAccount)ResolveFunction(NAME_XAM, 107);
pNetDll_XnpSaveMachineAccount NetDll_XnpSaveMachineAccount = (pNetDll_XnpSaveMachineAccount)NetDll_XnpSaveMachineAccountSaveVar;
static DWORD NetDll_XnpSaveMachineAccountOld[4];

HRESULT NetDll_XnpSaveMachineAccountHook(DWORD xamDebugLvl, PBYTE machineAcct) {
	DbgPrint("NetDll_XnpSaveMachineAccountHook has been called!!!!!");
	BYTE gamertagSha[0x10];
	XeCryptRandom(gamertagSha, 0x10);

	BYTE temp = 0;
	for (int i = 0; i<0x5; i++) {
		temp = (gamertagSha[i] & 0xE) + '0';
		SetMemory(&machineAcct[0x31 + i], &temp, 1);
	}
	BYTE checksum = 0;
	temp = 0;
	for (int i = 0; i<11; i++) {
		SetMemory(&temp, &machineAcct[0x2B + i], 1);
		checksum += temp - '0';
	}
	checksum %= 10;
	SetMemory(&machineAcct[0x36], &checksum, 1);

	return NetDll_XnpSaveMachineAccount(2, machineAcct);
}

void patchGold()
{
	DWORD XUCP = (DWORD)ResolveFunction("xam.xex", 0x212);
	*(int*)(XUCP + 0x140) = 0x39600001;
	*(int*)(XUCP + 0x1A0) = 0x39600001;
	*(int*)(XUCP + 0x1AC) = 0x39600001;
	*(int*)(XUCP + 0x1B4) = 0x39600001;
}

BOOL InitializeSystemXexHooks()
{
	// if(PatchModuleImport(NAME_XAM, NAME_KERNEL, 410, (DWORD)XexLoadImageFromMemoryHook) != S_OK) return S_FALSE;

	// Hook XamLoaderExecuteASyncChallengeHook
	//PatchInJump((DWORD*)0x8169CD98, (DWORD)XamLoaderExecuteAsyncChallengeHook, false);//
	PatchInJump((DWORD*)0x81A724D4, (DWORD)SpoofXamChallenge, FALSE);// dont know why I put this here?!

	// Patch xam's call to XexLoadExecutable
	if (PatchModuleImport(NAME_XAM, NAME_KERNEL, 408, (DWORD)XexLoadExecutableHook) != S_OK) return S_FALSE;

	// Patch xam's call to XexLoadImage
	if (PatchModuleImport(NAME_XAM, NAME_KERNEL, 409, (DWORD)XexLoadImageHook) != S_OK) return S_FALSE;

	// Patch xam's call to XeKeysExecute
	if (PatchModuleImport(NAME_XAM, NAME_KERNEL, 0x25F, (DWORD)XeKeysExecuteHook) != S_OK) return S_FALSE;

	return true;
}
BOOL InitializeSystemHooks()
{
	// Setup our static execution id
	DWORD ver = ((XboxKrnlVersion->Major & 0xF) << 28) | ((XboxKrnlVersion->Minor & 0xF) << 24) | (XboxKrnlVersion->Build << 8) | (XboxKrnlVersion->Qfe);
	ZeroMemory(&xeExecutionIdSpoof, sizeof(XEX_EXECUTION_ID));
	xeExecutionIdSpoof.Version = ver;
	xeExecutionIdSpoof.BaseVersion = ver;
	xeExecutionIdSpoof.TitleID = 0xFFFE07D1;

	// Patch xam's call to RtlImageXexHeaderField
	if (PatchModuleImport(NAME_XAM, NAME_KERNEL, 0x12B, (DWORD)RtlImageXexHeaderFieldHook) != S_OK) return S_FALSE;

	// Patch xam's call to XexCheckExecutablePrivilege
	if (PatchModuleImport(NAME_XAM, NAME_KERNEL, 404, (DWORD)XexCheckExecutablePrivilegeHook) != S_OK) return S_FALSE;
	patchGold();
	// Patch xam's call to XamUserCheckPriv
	//PatchInJump((PDWORD)(ResolveFunction("xam.xex", 0x212)), (DWORD)GoldSpoofHook, false);

	// All done
	return true;
}
