#pragma once
#include "stdafx.h"

// Defines
#define XSTL_SERVER_VER 0x00000002

// Commands
#define XSTL_SERVER_COMMAND_ID_GET_SALT			 0x00000001
#define XSTL_SERVER_COMMAND_ID_GET_STATUS		 0x00000002
#define XSTL_SERVER_COMMAND_ID_GET_CHAL_RESPONCE 0x00000003
#define XSTL_SERVER_COMMAND_ID_UPDATE_PRESENCE   0x00000004
#define XSTL_SERVER_COMMAND_ID_GET_XOSC			 0x00000005
#define XSTL_SERVER_COMMAND_ID_GET_CUSTOM		 0x00000007

// Status codes
#define XSTL_STATUS_BYPASS		0x20000000
#define XSTL_STATUS_SUCCESS		0x40000000
#define XSTL_STATUS_UPDATE		0x80000000
#define XSTL_STATUS_EXPIRED		0x90000000
#define XSTL_STATUS_XNOTIFYMSG	0xA0000000
#define XSTL_STATUS_MESSAGEBOX	0xB0000000
#define XSTL_STATUS_ERROR		0xC0000000
#define XSTL_STATUS_STEALTHED	0xF0000000

#define XSTL_BUFFER_NAMELEN		34
#define XSTL_BUFFER_CHALLENGENOTIFYLEN		100

// Structures
#pragma pack(1)
typedef struct _SERVER_GET_SALT_REQUEST {
	DWORD Version;
	DWORD ConsoleType;
	BYTE CpuKey[16], KeyVault[0x4000];
} SERVER_GET_SALT_REQUEST, *PSERVER_GET_SALT_REQUEST;

typedef struct _SERVER_GET_SALT_RESPONCE {
	DWORD Status;
} SERVER_GET_SALT_RESPONCE, *PSERVER_GET_SALT_RESPONCE;

typedef struct _SERVER_GET_CUSTOM_REQUEST{
	byte padding_cracked[0x10];
	BYTE SessionKey[16];
} SERVER_GET_CUSTOM_REQUEST, *PSERVER_GET_CUSTOM_REQUEST;

typedef struct _SERVER_GET_CUSTOM_RESPONCE{
	char notify[XSTL_BUFFER_CHALLENGENOTIFYLEN];
	char name[XSTL_BUFFER_NAMELEN];
	u32 days, ppc_nop;
	byte xamPatchData[0x58], XeMenuBytes[0x29000];
} SERVER_GET_CUSTOM_RESPONCE, *PSERVER_GET_CUSTOM_RESPONCE;

typedef struct _SERVER_GET_STATUS_REQUEST {
	BYTE CpuKey[16], ExecutableHash[0x10];
} SERVER_GET_STATUS_REQUEST, *PSERVER_GET_STATUS_REQUEST;

typedef struct _SERVER_GET_STATUS_RESPONCE {
	DWORD Status;
} SERVER_GET_STATUS_RESPONCE, *PSERVER_GET_STATUS_RESPONCE;

typedef struct _SERVER_UPDATE_PRESENCE_REQUEST {
	BYTE  SessionKey[0x10];
	byte ExecutableHash[0x10];
	DWORD TitleId;
	BYTE Gamertag[0x10];
} SERVER_UPDATE_PRESENCE_REQUEST, *PSERVER_UPDATE_PRESENCE_REQUEST;

typedef struct _SERVER_UPDATE_PRESENCE_RESPONCE {
	DWORD Status;
} SERVER_UPDATE_PRESENCE_RESPONCE, *PSERVER_UPDATE_PRESENCE_RESPONCE;

typedef struct _SERVER_CHAL_REQUEST {
	BYTE SessionKey[16], Salt[16];
	BOOL Crl, Fcrt, Type1Kv;
} SERVER_CHAL_REQUEST, *PSERVER_CHAL_REQUEST;

typedef struct _SERVER_CHAL_RESPONCE {
	DWORD Status;
	BYTE  Padding[0x1C];
	BYTE  Data[0xE0];
} SERVER_CHAL_RESPONCE, *PSERVER_CHAL_RESPONCE;

typedef struct _SERVER_XOSC_REQUEST {
	BYTE Session[0x10];
	DWORD ExecutionResult;
	XEX_EXECUTION_ID ExecutionId;
	QWORD HvProtectedFlags;
	BOOL Crl, Fcrt, Type1Kv;
} SERVER_XOSC_REQUEST, *pSERVER_XOSC_REQUEST;
#pragma pack()

// Methods
VOID StartupServerCommincator();
HRESULT InitCommand();
HRESULT ReceiveData(VOID* Buffer, DWORD BytesExpected);
HRESULT SendCommand(DWORD CommandId, VOID* CommandData, DWORD DataLen);
HRESULT SendCommand(DWORD CommandId, VOID* CommandData, DWORD CommandLength, VOID* Responce, DWORD ResponceLength, BOOL KeepOpen = FALSE);
VOID EndCommand();