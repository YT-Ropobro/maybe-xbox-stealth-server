#include "stdafx.h"
#pragma region Externs & Includes
extern HANDLE hXam;
extern BOOL isPlatinum;
extern BOOL isBypassed;
extern BOOL IsDevkit;
extern BOOL dashLoaded;
extern const int spPatchSz;
extern const int mpPatchSz;
extern const int awmpPatchSz;
extern const int ghostmpPatchSz;
extern const int awspPatchSz;
extern const int bypassDataSize;
extern BYTE spAddress[];
extern BYTE mpAddress[];
extern BYTE awmpAddress[];
extern BYTE ghostsAddress[];
extern BYTE awspAddress[];
MESSAGEBOX_RESULT g_mb_result;
XOVERLAPPED g_xol;
HANDLE thread;
DWORD threadID;
static BOOL isFrozen = FALSE;
static DWORD lastTitleID = 0;
typedef unsigned __int64 QWORD;
extern wchar_t challengeNotify[XSTL_BUFFER_CHALLENGENOTIFYLEN];
BYTE IdleARGB[] = { 0xFF, 0x76, 0x12, 0x76 };//761276 purple
BYTE InteractARGB[] = { 0xFF, 0x76, 0x12, 0x76 };// Button Press (dashuisk)
BYTE IdleRGB[] = { 0xFF, 0x76, 0x12, 0x76 };//
BYTE Background[] = { 0xFF, 0x00, 0x00, 0x00 };//black

BYTE IPAddress[4], ConsoleSerial[12], ConsoleIndex[12];
BYTE MachineId[] = {0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
BYTE Enet[] ={0x00, 0x1D, 0xD8, 0x00, 0x00, 0x00};

typedef struct _ACStruct{
	BYTE        OnlineIP[4];            //0x00-0x04 (Randomize)
	QWORD       MachineId;              //0x04-0x0C (Randomize)
	BYTE        Enet;                   //0x0C-0x12 (Randomize)
	SHORT       Padding1;               //0x12-0x14 (0x0000)
	FLOAT       fUnknown[2];            //0x14-0x1C (fUnknown[0] = *(float*)(0x849F6630); fUnknown[1] = *(float*)(0x849F6634);)
	SHORT       sUnknown;               //0x1C-0x1E (sUnknown = ((*(int*)0x8466D5DC) >> 10);)
	BYTE        RetailFlag;             //0x1E-0x1F (0x3)
	CHAR        ConsoleSerial[0xC];     //0x1F-0x2B (Randomize)
	CHAR        Padding2;               //0x2B-0x2C (0x00)
	CHAR        ConsoleId[0xC];         //0x2C-0x38 (Randomize)
	SHORT       KernalVersion;          //0x38-0x3A (0x42FE)
} ACStruct, *PAW_RESP;

extern DWORD ApplyPatches(CHAR* FilePath, const VOID* DefaultPatches = NULL);
extern void printBytes(PBYTE bytes, DWORD len);

VOID __cdecl APCWorker(void* Arg1, void* Arg2, void* Arg3) {

	// Call our completion routine if we have one
	if (Arg2)
		((LPOVERLAPPED_COMPLETION_ROUTINE)Arg2)((DWORD)Arg3, 0, (LPOVERLAPPED)Arg1);
}
//Ghosts Hook
NTSTATUS XBL_CushGetKeyHook(WORD KeyId, PVOID KeyBuffer, PDWORD keyLength){
if (KeyId == 0x14)
{
	XUSER_SIGNIN_INFO userInfo;
	XamUserGetSigninInfo(0, XUSER_GET_SIGNIN_INFO_ONLINE_XUID_ONLY, &userInfo);
	BYTE gamertagSha[0x10];
	XeCryptSha((PBYTE)userInfo.szUserName, strlen(userInfo.szUserName), NULL, NULL, NULL, NULL, gamertagSha, 0x10);
	BYTE temp = 0;
	for (int i = 0; i<0xC; i++){
	temp = (gamertagSha[i] & 0xE) + '0';
	SetMemory(&((BYTE*)(KeyBuffer))[i], &temp, 1);
	}
}
else return XeKeysGetKey(KeyId, KeyBuffer, keyLength);
return STATUS_SUCCESS;
}
DWORD XSecurityCreateProcessHook(DWORD dwHardwareThread)
{
	return ERROR_SUCCESS;
}
VOID XSecurityCloseProcessHook(){}

DWORD XSecurityVerifyHook(DWORD dwMilliseconds, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {

	// Queue our completion routine
	if (lpCompletionRoutine)
		NtQueueApcThread((HANDLE)-2, (PIO_APC_ROUTINE)APCWorker, lpOverlapped, (PIO_STATUS_BLOCK)lpCompletionRoutine, 0);

	// All done
	return ERROR_SUCCESS;
}
DWORD XSecurityGetFailureInfoHook(PXSECURITY_FAILURE_INFORMATION pFailureInformation)
{
	if (pFailureInformation->dwSize != 0x18) return ERROR_NOT_ENOUGH_MEMORY;
	pFailureInformation->dwBlocksChecked = 0;
	pFailureInformation->dwFailedReads = 0;
	pFailureInformation->dwFailedHashes = 0;
	pFailureInformation->dwTotalBlocks = 0;
	pFailureInformation->fComplete = TRUE;
	return ERROR_SUCCESS;
}

DWORD XexGetProcedureAddressHook(HANDLE hand, DWORD dwOrdinal, PVOID* pvAddress)
{
	if (hand == hXam) {
		switch (dwOrdinal) {
		case 0x9BB:
			*pvAddress = XSecurityCreateProcessHook;
			return 0;
		case 0x9BC:
			*pvAddress = XSecurityCloseProcessHook;
			return 0;
		case 0x9BD:
			*pvAddress = XSecurityVerifyHook;
			return 0;
		case 0x9BE:
			*pvAddress = XSecurityGetFailureInfoHook;
			return 0;
		}
	}
	//DbgPrint("XexGetProcedureAddressHook [pvAddress]: 0x%p", pvAddress);
	return XexGetProcedureAddress(hand, dwOrdinal, pvAddress);
}

NTSTATUS XeKeysGetKeyHookBO2(WORD KeyId, PVOID KeyBuffer, PDWORD keyLength){
	if (KeyId == 0x14){
		XUSER_SIGNIN_INFO userInfo;
		XamUserGetSigninInfo(0, XUSER_GET_SIGNIN_INFO_ONLINE_XUID_ONLY, &userInfo);

		BYTE gamertagSha[0x10];
		XeCryptSha((PBYTE)userInfo.szUserName, strlen(userInfo.szUserName), NULL, NULL, NULL, NULL, gamertagSha, 0x10);
		BYTE temp = 0;
		for (int i = 0; i<0xC; i++){
			temp = (gamertagSha[i] & 0xE) + '0';
			SetMemory(&((BYTE*)(KeyBuffer))[i], &temp, 1);
		}
	}
	else return XeKeysGetKey(KeyId, KeyBuffer, keyLength);
	return ERROR_SUCCESS;
}

HRESULT XeKeysGetConsoleIDHookBO2(PBYTE databuffer OPTIONAL, char* szBuffer OPTIONAL) {

	XE_CONSOLE_ID consoleID;
	XeKeysGetConsoleID((PBYTE)&consoleID, NULL);

	XUSER_SIGNIN_INFO userInfo;
	XamUserGetSigninInfo(0, XUSER_GET_SIGNIN_INFO_ONLINE_XUID_ONLY, &userInfo);

	BYTE gamertagSha[0x10];
	XeCryptSha((PBYTE)userInfo.szUserName, strlen(userInfo.szUserName), NULL, NULL, NULL, NULL, gamertagSha, 0x10);
	consoleID.asBits.MacIndex3 = gamertagSha[0];
	consoleID.asBits.MacIndex4 = gamertagSha[1];
	consoleID.asBits.MacIndex5 = gamertagSha[2];

	SetMemory(databuffer, &consoleID, 0x5);
	return ERROR_SUCCESS;
}

int NetDll_XNetXnAddrToMachineIdHookBO2(XNCALLER_TYPE xnc, XNADDR * pxnaddr, ULONGLONG * pqwMachineId){

	int rett = NetDll_XNetXnAddrToMachineId(xnc, pxnaddr, pqwMachineId);

	XUSER_SIGNIN_INFO userInfo;
	XamUserGetSigninInfo(0, XUSER_GET_SIGNIN_INFO_ONLINE_XUID_ONLY, &userInfo);

	BYTE gamertagSha[0x10];
	XeCryptSha((PBYTE)userInfo.szUserName, strlen(userInfo.szUserName), NULL, NULL, NULL, NULL, gamertagSha, 0x10);
	SetMemory(pqwMachineId + 5, gamertagSha, 0x3);

	return rett;
}

typedef HRESULT(*pXamInputGetState)(QWORD r3, QWORD r4, QWORD r5);
pXamInputGetState XamInputGetState = (pXamInputGetState)ResolveFunction(NAME_XAM, 401);

HRESULT XamInputGetStateHook(QWORD r3, QWORD r4, QWORD r5){
	if (isFrozen){
		return 0;
	}
	HRESULT ret = XamInputGetState(r3, r4, r5);
	return ret;
}

inline DWORD GoldSpoofHook(DWORD dwUserIndex, XPRIVILEGE_TYPE PrivilegeType, PBOOL pfResult)
{
	if (PrivilegeType == XPRIVILEGE_TYPE::XPRIVILEGE_COMMUNICATIONS_FRIENDS_ONLY
		|| PrivilegeType == XPRIVILEGE_TYPE::XPRIVILEGE_PROFILE_VIEWING_FRIENDS_ONLY
		|| PrivilegeType == XPRIVILEGE_TYPE::XPRIVILEGE_USER_CREATED_CONTENT_FRIENDS_ONLY
		|| PrivilegeType == XPRIVILEGE_TYPE::XPRIVILEGE_PRESENCE_FRIENDS_ONLY
		|| PrivilegeType == XPRIVILEGE_TYPE::XPRIVILEGE_VIDEO_COMMUNICATIONS_FRIENDS_ONLY)
		*pfResult = FALSE;
	else
		*pfResult = TRUE;

	return 0;
}

unsigned long XeXGetModuleHandleHook(char* ModuleName)
{
	if (strcmp(ModuleName, "xbdm.xex") == 0)
		return 0;
}

int XNetXnAddrToMachineIdHook(XNCALLER_TYPE xnc, XNADDR  pxnaddr, unsigned long long MachineId)
{
	srand((unsigned int)time(0));
	MachineId = 0xFA00000000000000 | (0x2000000 | rand() % 0x7FFFFF);
	return 0;
}
unsigned long XeKeysGetKeyHook(unsigned short key, unsigned char* buffer, PDWORD len) //
{
	if (key == 0x14)
	{
		srand((unsigned int)time(0));
		for (int i = 0x00; i < 0xC; i++) buffer[i] = rand() % 0x7F;
		return 0L;
	}
	return XeKeysGetKey(key, buffer, len);
}

long XeKeysGetConsoleIDHook(unsigned char* buffer, int Unknown) //81A74FE4
{
	srand((unsigned int)time(0));
	for (int i = 0x00; i < 0xC; i++) buffer[i] = rand() % 0x7F;
	return 0;
}

HRESULT XNetLogonGetMachineIDHook(QWORD* machineID){

	QWORD machID=0;
	HRESULT rett = XNetLogonGetMachineID(&machID);

	XUSER_SIGNIN_INFO userInfo;
	XamUserGetSigninInfo(0, XUSER_GET_SIGNIN_INFO_ONLINE_XUID_ONLY, &userInfo);

	BYTE gamertagSha[0x10];
	XeCryptSha((PBYTE)userInfo.szUserName, strlen(userInfo.szUserName), NULL, NULL, NULL, NULL, gamertagSha, 0x10);
	SetMemory(machineID+5, gamertagSha, 0x3);

	return rett;
}

unsigned char Response[] = {
0x00, 0x00, 0x00, 0x00, //IP Address
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //MachineId
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //Enet
0x00, 0x00, //Padding
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //flUnknown
0x00, 0x00, //shUnknown
0x03, //Retail Flag
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //Console Serial
0x00, //Padding
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //Console Index
0x42, 0xFE //Kernel Version
};
void randomize()
{
	BYTE IPAddress[4], MachineId[8], Enet[8], ConsoleKey[13], ConsoleIndex[12], padding0[2], padding1[8];
	for (int i = 0; i < 2; i++)IPAddress[i] = rand() % 90;
	for (int i = 0; i < 2; i++)MachineId[i] = rand() % 90;
	for (int i = 0; i < 1; i++)Enet[i] = rand() % 90;
	for (int i = 0; i < 3; i++)ConsoleIndex[i] = rand() % 90;
	for (int i = 0; i < 3; i++)ConsoleKey[i] = rand() % 90;
	for (int i = 0; i < 2; i++)padding0[i] = rand() % 90;
	for (int i = 0; i < 8; i++)padding1[i] = rand() % 90;
	memcpy(Response + 0x2, &IPAddress, 2);
	memcpy(Response + 0x6, &MachineId, 2);
	memcpy(Response + 0x10, &Enet, 1);
	memcpy(Response + 0x29, &ConsoleKey, 3);
	memcpy(Response + 0x33, &ConsoleIndex, 3);
	memcpy(Response + 0x1C, &padding0, 2);
	memcpy(Response + 0x14, &padding1, 8);
}
unsigned long XexGetModuleHandleHook(char* ModuleName) {
	if(strcmp(ModuleName, "xbdm.xex") == 0) {
		DbgPrint("Returned XBDM as 0");
		return 0;
	} else return (unsigned long)GetModuleHandle(ModuleName);
}


//AW
inline DWORD GoldSpoofHook2(DWORD dwUserIndex, XPRIVILEGE_TYPE PrivilegeType, PBOOL pfResult)
{
	*pfResult = true;
	return ERROR_SUCCESS;
}
inline __declspec() bool Live_GetConsoleDetailsSavestub(unsigned char internalIP[4], unsigned char onlineIP[4], unsigned long long *machineIDH, unsigned long long *null, unsigned long long *enet)
{
	__asm
	{
		nop
			nop
			nop
			nop
			nop
			nop
			nop
			blr
	}
}
bool Live_GetConsoleDetailsHookAW(unsigned char internalIP[4], unsigned char onlineIP[4], unsigned long long *machineIDH, unsigned long long *null, unsigned long long *enet)
{
	srand(time(0));
	int iTargetAddress = 0;
	__asm mflr      iTargetAddress
	if (iTargetAddress == 0x822C9FF8 || iTargetAddress == 0x822C9908)
	{
		for (int i = 0; i < 4; i++)
		{
			internalIP[i] = rand() % 0xFF; onlineIP[i] = rand() % 0xFF;
		}
		*enet = 0x001DD8000000 | rand() % 0x7FFFFF;
		return true;
	}
	return Live_GetConsoleDetailsSavestub(internalIP, onlineIP, machineIDH, null, enet);
}

//End AW

DWORD NetDll_XNetXnAddrToMachineIdHook(DWORD XNC, const XNADDR * pXNAddr, QWORD * pqwMachineID)
{
	srand((unsigned)time(NULL));
	*(QWORD*)pqwMachineID = 0xFA00000000000000 | (0x2000000 | rand() % 0x7FFFFF);
	return 0;
}

bool NullHeader = TRUE;
VOID __declspec(naked) XHTTPConnectStub(...) {
	__asm
	{
		li r3, 1
		nop
		nop
		nop
		nop
		nop
		nop
		blr
	}
}
VOID __declspec(naked) XHTTPOpenRequestUsingMemoryStub(...) {
	__asm
	{
		li r3, 2
		nop
		nop
		nop
		nop
		nop
		nop
		blr
	}
}
VOID XHTTPOpenRequestUsingMemoryHook(SOCKET hConnect, const CHAR *pcszVerb, const CHAR *pcszObjectName, const CHAR *pcszVersion, const CHAR *pcszReferrer, const CHAR **ppReserved, DWORD dwFlags) {
	if (strncmp(pcszObjectName + 0x15, "dashhome.xml", 0xC) == 0) pcszObjectName = "/assets/dashhome.xml", NullHeader = TRUE;
	if (strncmp(pcszObjectName + 0x15, "exl-HELP-on-360.xml", 0x13) == 0) pcszObjectName = "/assets/exl-HELP-on-360.xml", NullHeader = TRUE;
	if (strncmp(pcszObjectName + 0x15, "exl-GamesMarketplace.xml", 0x18) == 0) pcszObjectName = "/assets/exl-GamesMarketplace.xml", NullHeader = TRUE;
	if (strncmp(pcszObjectName + 0x15, "DashVideoMP-London.xml", 0x16) == 0) pcszObjectName = "/assets/DashVideoMp-London.xml", NullHeader = TRUE;
	XHTTPOpenRequestUsingMemoryStub(hConnect, pcszVerb, pcszObjectName, pcszVersion, pcszReferrer, ppReserved, dwFlags);
}
VOID __declspec(naked) XHTTPSendRequestStub(...) {
	__asm
	{
		li r3, 3
		nop
		nop
		nop
		nop
		nop
		nop
		blr
	}
}
VOID XHTTPSendRequestHook(SOCKET hRequest, const CHAR *pcszHeaders, DWORD dwHeadersLength, const VOID *lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) {
	if (NullHeader) pcszHeaders = NULL;
	XHTTPSendRequestStub(hRequest, pcszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
	NullHeader = FALSE;
}
DWORD NetDll_XHttpConnectHook(SOCKET Socket, PCHAR pchName, WORD Port, DWORD dwCallLength) {
	if (strcmp(pchName, "manifest.xboxlive.com") == 0)pchName = "assets.silent.hosted.nfoservers.com", dwCallLength = 0x000000001, Port = 0x50;
	return ((DWORD(*)(...))0x9293AFBC)(XNCALLER_TITLE, Socket, pchName, Port, dwCallLength);
}
DWORD XML_Start() {
	HookFunctionStart((PDWORD)0x92247B08, (PDWORD)XHTTPConnectStub, (DWORD)NetDll_XHttpConnectHook);//old 92247D68
	HookFunctionStart((PDWORD)0x92247B60, (PDWORD)XHTTPOpenRequestUsingMemoryStub, (DWORD)XHTTPOpenRequestUsingMemoryHook);//old 92247DC0
	HookFunctionStart((PDWORD)0x92247BB8, (PDWORD)XHTTPSendRequestStub, (DWORD)XHTTPSendRequestHook);//old 92247E18
	return NULL;
}
VOID SetDashUI() {
	/*Dash titles*/ //17599
	memcpy((BYTE*)0x92ACAA30, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((BYTE*)0x92B570E2, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((BYTE*)0x92C58F28, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((BYTE*)0x92C72B73, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((BYTE*)0x92DB07E5, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((BYTE*)0x92F0E15B, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((BYTE*)0x92F54622, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((BYTE*)0x92F5F852, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((BYTE*)0x92BACFC0, IdleARGB, ARRAYSIZE(IdleARGB));// button press FF76B900
	memcpy((BYTE*)0x92C58F24, IdleARGB, ARRAYSIZE(IdleARGB));// button press FF1CB61C
	memcpy((BYTE*)0x92F0E16F, IdleARGB, ARRAYSIZE(IdleARGB));// button press FF1CB61C
	memcpy((BYTE*)0x81B9D432, IdleARGB, ARRAYSIZE(IdleARGB));// Gamercard Gold
	memcpy((BYTE*)0x81B9D436, IdleARGB, ARRAYSIZE(IdleARGB));// Gamercard Gold
	memcpy((BYTE*)0xC025D43A, IdleARGB, ARRAYSIZE(IdleARGB));// Gamercard Silver
	memcpy((BYTE*)0xC2317DE7, IdleARGB, ARRAYSIZE(IdleARGB));// Gamercard Silver 
															 /*Dash and setting Background*/ // 17559
	BYTE Data[0x13];
	memcpy((PDWORD)0x92B19236, Data, 0x13);// aura_background nulled
	memcpy((PVOID*)0x92B4FDA7, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92F58323, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FDAF, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FDB3, Background, ARRAYSIZE(Background));
	/////////////////////////////////////////////////////
	//*Settings background*/
	memcpy((PVOID*)0x92B4FD9B, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92106CE7, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FDA7, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92F58323, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FDAB, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FD9F, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B53D33, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B55FA9, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B9524B, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B95A6D, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92C58F84, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92C6C662, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92CBE9D8, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92CC7138, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92CE54F8, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92D1DB13, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92D1E13C, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92D566BB, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92D56926, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92D56B48, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92D56FAA, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92D56D79, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92D57213, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92D5749E, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92F0E053, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92F54632, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FD9F, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FDA3, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FD93, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FD97, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FD9F, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FD9F, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FDAF, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FDB3, Background, ARRAYSIZE(Background));
	memcpy((PVOID*)0x92B4FE03, Background, ARRAYSIZE(Background));
	///////////////////////////////////////////////////
	//* PNG's*/
	memcpy((PVOID*)0x92D2ACDC, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0x92D2AF9D, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0x92D2B12B, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0x92D2B2EC, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0x92DB07DF, IdleARGB, ARRAYSIZE(IdleARGB));
	// Light Green
	/*memcpy((PVOID*)0xC092E8C4, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC09B9F2E, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC0FA992C, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC0FA9968, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC0FA99A4, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC1197298, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC23DA028, IdleARGB, ARRAYSIZE(IdleARGB));*/
}
VOID SetHUDUI() {
	// Idle
	memcpy((PVOID*)0xC098E638, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC09BAEDE, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC10712EC, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC1073E94, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC1074394, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC10754F4, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC1075F54, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC108A9DC, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC108B910, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC108CB7C, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC108D110, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC10D0AF4, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC1117AE4, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC1197248, IdleARGB, ARRAYSIZE(IdleARGB));
	memcpy((PVOID*)0xC24D80E2, IdleARGB, ARRAYSIZE(IdleARGB));
	// Press
	memcpy((PVOID*)0xC09B9F0E, InteractARGB, ARRAYSIZE(InteractARGB));
	memcpy((PVOID*)0xC0F99000, InteractARGB, ARRAYSIZE(InteractARGB));
	memcpy((PVOID*)0xC0FA97D8, InteractARGB, ARRAYSIZE(InteractARGB));
	memcpy((PVOID*)0xC1075F48, InteractARGB, ARRAYSIZE(InteractARGB));
	memcpy((PVOID*)0xC111ECC0, InteractARGB, ARRAYSIZE(InteractARGB));
	memcpy((PVOID*)0xC1197278, InteractARGB, ARRAYSIZE(InteractARGB));
	memcpy((PVOID*)0xC212F16F, InteractARGB, ARRAYSIZE(InteractARGB));
}
VOID dashtext() {
	// Kernel At 0x300000C1
	BYTE download[] = { 0x48, 0x6f, 0x6f, 0x6b, 0x61, 0x68, 0x20, 0x64, 0x6F, 0x77, 0x6E, 0x6C, 0x6F, 0x61, 0x64, 0x20, 0x00, 0x41, 0x6C, 0x72, 0x65, 0x61, 0x64, 0x79, 0x20, 0x68, 0x61, 0x76, 0x65, 0x20, 0x61, 0x6E, 0x20, 0x55, 0x73, 0x65, 0x4C, 0x65, 0x73, 0x73, 0x20, 0x20, 0x20, 0x70, 0x72, 0x6F, 0x66, 0x69, 0x6C, 0x65, 0x3F };//55 73 65 4c 65 73 73 20 20 20
	char* createprofile = "Create SHiT   ";
	//memcpy((BYTE*)0x92D84DC8, Pic, sizeof(AvatarPic));
	//memcpy((LPVOID)0x92AC5EFB, createprofile, 15);
	memcpy((LPVOID)0x92BAE010, " WeLcOME To    ", 19);
	memcpy((LPVOID)0x92BADFFC, "Silent Live        ", 19);
	memcpy((LPVOID)0x92D2CA2E, "OpenBitch", 9);
	memcpy((LPVOID)0x92D2C9DC, "CloseBitch", 10);
	//memcpy((LPVOID)0x92BADEEB, download, 51);//0x92BADEEB or 0x92BADF83
}
VOID dash() {
	XML_Start();
	dashtext();
	SetHUDUI();
	SetDashUI();
}
VOID patchlabels2() {
	char* XboxGaA = "Silent Menu ";
	SetMemory((LPVOID)0x9140A095, XboxGaA, 13); // -- Turn Off Games & Apps 17502
												//123456789112345678
	char* XboxAM = "Account STUFF     ";
	SetMemory((LPVOID)0x91411A16, XboxAM, 18); // -- Account Management : 17502
	char* XboxHME = "LIVE";
	SetMemory((LPVOID)0x9140A086, XboxHME, 4); // -- Home Tab : 17502
											   //1234567891123456
	char* XboxToC = "Exit SilenTLive  ";
	SetMemory((LPVOID)0x91411A9B, XboxToC, 16);
	SetMemory((LPVOID)0x91411A9B, XboxToC, 16); // -- Turn Off Console 17502
	SetMemory((LPVOID)0x91411FAF, XboxToC, 16); // -- Turn Off Console 17502
												//12345678
	char* GuideBladeLblText = "SileNT  ";//[8] chars 
	SetMemory((LPVOID)0x9140A05C, GuideBladeLblText, 8); // -- Settings Tab 17502
														 //123456789114584
	char* GuideButtonSS = "UR SeTtings!   "; // [15] Chars
	SetMemory((LPVOID)0x914119F7, GuideButtonSS, 15); // -- System Settings 17502
	  //1234567891
	 //char* XboxHome = "SiLeNTLIive"; 
	 //SetMemory((LPVOID)0x91409FF9, XboxHome, 10); // -- (Y) Xbox Home : 17502
	 // Hook onto Xbox Guide buttons
}
VOID InitializeTitleSpecificHooks(PLDR_DATA_TABLE_ENTRY ModuleHandle){
	// Hook any calls to XexGetProcedureAddress
	int Color = 0xFF660066;
	//#ifdef XOSC_ENABLED
	PatchModuleImport(ModuleHandle, NAME_KERNEL, 407, (DWORD)XexGetProcedureAddressHook);
	//#endif
	// If this module tries to load more modules, this will let us get those as well
	PatchModuleImport(ModuleHandle, NAME_KERNEL, 408, (DWORD)XexLoadExecutableHook);
	PatchModuleImport(ModuleHandle, NAME_KERNEL, 409, (DWORD)XexLoadImageHook);
	PatchModuleImport(ModuleHandle, NAME_XAM, 401, (DWORD)XamInputGetStateHook);
	XEX_EXECUTION_ID* pExecutionId = (XEX_EXECUTION_ID*)RtlImageXexHeaderField(ModuleHandle->XexHeaderBase, 0x00040006);
	if (pExecutionId == 0) return;
	bool test = 0;
	if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"dash.social.lex") == 0) {

		//more tabs
		*(int*)0x9AFC4876 = Color;
		//PatchInJump((PDWORD)0x92247D68, (DWORD)NetDll_XHttpConnectHook2, false);
	}
		if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"hud.xex") == 0 && !IsDevkit){
			//HUD_PatchLabels();
			patchlabels2();

		}
	if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"dash.xex") == 0 || wcscmp(ModuleHandle->BaseDllName.Buffer, L"xshell.xex") == 0 || pExecutionId->TitleID == FREESTYLEDASH){
		dashLoaded = TRUE;
		lastTitleID = pExecutionId->TitleID;
		PatchInJump((PDWORD)0x81740960, (DWORD)NetDll_XNetXnAddrToMachineIdHook, false);
		dash();
		test = 0;
	}
	else 
	{
		if (pExecutionId->TitleID == COD_BO2)
		{
			Sleep(1000);
			if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0)
			{
				*(int*)0x824A7620 = 0x60000000;
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
				memcpy((BYTE*)0x822D19E0, Data, 4);	//New Ban Check 5 
				memcpy((BYTE*)0x82599630, Data, 4);	//New Ban Check 6 
				SetMemory((PVOID)0x825C6070, Data, 4); // Disable Probation
				XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, 0, 2, L"Silent - BOII Bypassed!", NULL);
			}
		}
		
		if(pExecutionId->TitleID == COD_GHOSTS)
		{
			Sleep(1000);
			if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0)
			{
				*(DWORD*)0x82627628 = 0x38600000;
				*(DWORD*)0x82627634 = 0x39600001;
				*(DWORD*)0x82627650 = 0x38600002;
				*(int*)0x826276DC = 0x61490000;
				*(long long*)0x82627684 = 0x8921005060000000;
				*(long long*)0x826276DC = 0x8921005060000000;
				PatchInJump((PDWORD)(ResolveFunction("xam.xex", 0x195)), (DWORD)XeXGetModuleHandleHook, false);
				Sleep(2000);
				PatchInJump((PDWORD)0x81A74DB4, (DWORD)XeKeysGetKeyHook, false); //XAM
				PatchInJump((PDWORD)0x81A74FE4, (DWORD)XeKeysGetConsoleIDHook, false); //XAM
				PatchInJump((PDWORD)0x8173D258, (DWORD)XNetXnAddrToMachineIdHook, false);
				Sleep(500);
				*(DWORD*)0x8226539B = 0x3B600001; // Advanced UAV 1
				*(DWORD*)0x82265793 = 0x3B600001; // Advanced UAV 2
				*(DWORD*)0x822657FF = 0x3B600001; // Advanced UAV 3
				*(DWORD*)0x8227F198 = 0x38600001; // Laser
				*(DWORD*)0x8226D2B4 = 0x60000000; // Redboxes
				*(DWORD*)0x822C8F3C = 0x60000000; // No Recoil
				XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, 0, 2, L"Silent - Ghosts Bypassed!", NULL);
			}
		}

		if(pExecutionId->TitleID == COD_AW)
		{
			Sleep(1000);
			if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0)
			{
				Sleep(1000);
				*(long long*)0x822CA190 = 0x8921005060000000;
				*(int*)0x822CA18C = 0x48000010;
				*(int*)0x822CA184 = 0x38600000;
				*(int*)0x822CA0EC = 0x3920331C;
				*(PBYTE)0x8233B0E7 = 0x00;
				PatchInJump((PDWORD)0x8173D258, (DWORD)XNetXnAddrToMachineIdHook, false);
				*(PDWORD)0x826476A0 = 0x60000000;		// Cross Hairs One
				*(PDWORD)(0x826476A0 + 4) = 0x39600000; // Cross Hairs Two
				*(PDWORD)0x8260659C = 0x38C00005;		// Players Outline
				*(PDWORD)0x82626F6C = 0x38C0000F;		// Weapons Outline
				*(PDWORD)0x8262FB0C = 0x60000000;		// Red Boxes
				*(PDWORD)0x82648CEC = 0x60000000;		// No Recoil
				*(PBYTE)(0x826352A4 + 3) = 1;			// UAV
				*(DWORD*)0x826352A8 = 0x3B200001;		// UAV
				Sleep(2000);
				PatchInJump((PDWORD)(ResolveFunction("xam.xex", 0x195)), (DWORD)XeXGetModuleHandleHook, false);
				XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, 0, 2, L"Silent - AW Bypassed!", NULL);
			}
		}
	}
}