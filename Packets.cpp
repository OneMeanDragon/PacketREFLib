#include "includes.h"
#include <oleauto.h>

#define BNET_PROTO						0xFF
#define BOTNET_PROTO					0x01

#define ID_SID_NULL						0x00
#define ID_SID_CLIENTID					0x05
#define ID_SID_STARTVERSIONING			0x06
#define ID_SID_REPORTVERSION			0x07
#define ID_SID_GETADVLISTEX				0x09
#define ID_SID_ENTERCHAT				0x0A
#define ID_SID_GETCHANNELLIST			0x0B
#define ID_SID_JOINCHANNEL				0x0C
#define ID_SID_CHATCOMMAND				0x0E
#define ID_SID_CHATEVENT				0x0F
#define ID_SID_LEAVECHAT				0x10
#define ID_SID_LOCALEINFO				0x12
#define ID_SID_FLOODDETECTED			0x13
#define ID_SID_UDPPINGRESPONSE			0x14
#define ID_SID_CHECKAD					0x15
#define ID_SID_CLICKAD					0x16
#define ID_SID_READMEMORY				0x17
//#define ID_SID_REGISTRY				0x18 //gone to the ages
#define ID_SID_MESSAGEBOX				0x19
#define ID_SID_STARTADVEX2				0x1A
#define ID_SID_GAMEDATAADDRESS			0x1B
#define ID_SID_STARTADVEX3				0x1C
#define ID_SID_LOGONCHALLENGEEX			0x1D
#define ID_SID_CLIENTID2				0x1E
#define ID_SID_LEAVEGAME				0x1F
#define ID_SID_ANNOUNCEMENT				0x20
#define ID_SID_DISPLAYAD				0x21
#define ID_SID_NOTIFYJOIN				0x22
#define ID_SID_WRITECOOKIE				0x23
#define ID_SID_READCOOKIE				0x24
#define ID_SID_PING						0x25
#define ID_SID_READUSERDATA				0x26
#define ID_SID_WRITEUSERDATA			0x27
#define ID_SID_LOGONCHALLENGE			0x28
#define ID_SID_LOGONRESPONSE			0x29
#define ID_SID_CREATEACCOUNT			0x2A
#define ID_SID_SYSTEMINFO				0x2B
#define ID_SID_GAMERESULT				0x2C
#define ID_SID_GETICONDATA				0x2D
#define ID_SID_GETLADDERDATA			0x2E
#define ID_SID_FINDLADDERUSER			0x2F
#define ID_SID_CDKEY					0x30
#define ID_SID_CHANGEPASSWORD			0x31
//#define ID_SID_CHECKDATAFILE			0x32 //Not in use [SID_CHECKDATAFILE2]
#define ID_SID_GETFILETIME				0x33
//#define ID_SID_QUERYREALMS			0x34 //Not in use [SID_QUERYREALMS2]
#define ID_SID_PROFILE					0x35
#define ID_SID_CDKEY2					0x36
//SID_UNKNOWN_37						0x37
//SID_UNKNOWN_38						0x38
//SID_UNKNOWN_39						0x39
#define ID_SID_LOGONRESPONSE2			0x3A
//SID_UNKNOWN_3B						0x3B
#define ID_SID_CHECKDATAFILE2			0x3C
#define ID_SID_CREATEACCOUNT2			0x3D
#define ID_SID_LOGONREALMEX				0x3E
//#define ID_SID_STARTVERSIONING2		0x3F //Unknowen
#define ID_SID_QUERYREALMS2				0x40
#define ID_SID_QUERYADURL				0x41
//#define ID_SID_CDKEY3					0x42 //Not in use
//SID_WARCRAFTUNKNOWN					0x43 //Unknowen
//SID_WARCRAFTGENERAL					0x44 //Zug Zug
#define ID_SID_NETGAMEPORT				0x45
#define ID_SID_NEWS_INFO				0x46
//										0x47
//										0x48
//										0x49
#define ID_SID_OPTIONALWORK				0x4A
#define ID_SID_EXTRAWORK				0x4B
#define ID_SID_REQUIREDWORK				0x4C
//										0x4D
//SID_TOURNAMENT						0x4E
//										0x4F
#define ID_SID_AUTHINFO					0x50
#define ID_SID_AUTH_CHECK				0x51
#define ID_SID_AUTH_ACCOUNTCREATE		0x52
#define ID_SID_AUTH_ACCOUNTLOGON		0x53
#define ID_SID_AUTH_ACCOUNTLOGONPROOF	0x54

/*			MCP Packets				  */
#define ID_MCP_STARTUP					0x01
#define ID_MCP_CHARCREATE				0x02
#define ID_MCP_CREATEGAME				0x03
#define ID_MCP_JOINGAME					0x04
#define ID_MCP_GAMELIST					0x05
#define ID_MCP_GAMEINFO					0x06
#define ID_MCP_CHARLOGON				0x07
#define ID_MCP_CHARDELETE				0x0A
#define ID_MCP_REQUESTLADDERDATA		0x11
#define ID_MCP_MOTD						0x12
#define ID_MCP_CANCELGAMECREATE			0x13
#define ID_MCP_CHARRANK					0x16
#define ID_MCP_CHARUPGRADE				0x18
#define ID_MCP_CHARLIST2				0x19

/*			BOTNET Packets			  */
#define ID_BOTNET_KEEPALIVE				0x00
#define ID_BOTNET_LOGON					0x01
#define ID_BOTNET_STATSUPDATE			0x02
#define ID_BOTNET_DATABASE				0x03
#define ID_BOTNET_COMMAND_DB			0x04
//#define ID_BOTNET_CYCLE				0x05 //Defunct
#define ID_BOTNET_USER_LIST				0x06
#define ID_BOTNET_COMMAND_ALL			0x07
#define ID_BOTNET_COMMAND_TO			0x08
#define ID_BOTNET_DATABASE_CHPW			0x09
#define ID_BOTNET_CLIENT_VERSION		0x0A
#define ID_BOTNET_CHAT					0x0B
//#define ID_BOTNET_ADMIN				0x0C //Unknowen atm
#define ID_BOTNET_ACCOUNT				0x0D
//#define ID_BOTNET_DATABASE_CHMO		0x0E //Defunct
#define ID_BOTNET_CHAT_OPTIONS			0x10

#define BOTNET_LEN_POS					2
#define BOTNET_BASEHEAD_LEN				4
#define BOTNET_ACCOUNT_MAX				16
#define BOTNET_NAME_MAX					32
#define BOTNET_PASSWORD_MAX				64
#define BOTNET_BNET_NAME_MAX			20
#define BOTNET_BNET_CHANNELNAME_MAX		36
#define BOTNET_DB_PASS_MAX				96
#define BOTNET_USERMASK_MAX				40
#define BOTNET_FLAGSTR_MAX				28
#define BOTNET_COMMENT_MAX				64
#define BOTNET_COMMAND_MAX				384
#define BOTNET_MESSAGE_MAX				496

#define BNET_HEAD_LEN					4
#define BNET_LEN_POS					2
#define BNET_UNKSTR_LEN					255
#define BNET_FILEPATH_MAX				256
#define BNET_MEMORYBLOCK_LEN			1024
#define BNET_USERNAME_MAX				64
#define BNET_STATSTRING_MAX				128
#define BNET_GAMENAME_MAX				(BNET_USERNAME_MAX / 2)
#define BNET_CHANNELNAME_MAX			(BNET_USERNAME_MAX / 2)
#define BNET_CMESSAGE_MAX				225
#define BNET_CDKEY_MAX					27
#define BNET_CDKEYOWNER_MAX				16
#define SW_LEN							2
#define DW_LEN							4
#define SHA_LEN							(DW_LEN * 5)
#define MCPC1_LEN						(DW_LEN * 2)
#define MCPC2_LEN						(DW_LEN * 12)
#define KEY_HASH_LEN					(SHA_LEN + (DW_LEN * 4))
#define NLS_SIGNATURE_LEN				128
#define NLS_SALT_LEN					32

#pragma region "TimeZone Data for SID_AUTHINFO"

unsigned int GetBias()
{
	TIME_ZONE_INFORMATION tz;
	unsigned int dwReply = GetTimeZoneInformation(&tz);
	return (tz.Bias);
}

#pragma endregion

#pragma region "SystemTime and FileTime for SID_LOCALEINFO"

FILETIME SystemTimeFT()
{
	SYSTEMTIME tmp;
	FILETIME out;
	GetSystemTime(&tmp);
	SystemTimeToFileTime(&tmp, &out);
	return out;
}

FILETIME LocalTimeFT()
{
	SYSTEMTIME tmp;
	FILETIME out;
	GetLocalTime(&tmp);
	SystemTimeToFileTime(&tmp, &out);
	return out;
}

#pragma endregion

#pragma region "BNCS PACKET LISTING"

void VB6_API2 BNCS_INIT(const SOCKET s)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BNCS_INIT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	unsigned char packet_buffer[1];
	ZeroMemory(packet_buffer, 1);
	packet_buffer[0] = 0x1;
	send(s, (const char *)packet_buffer, 1, 0);

}

void VB6_API2 SID_NULL(const SOCKET s)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_NULL: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_NULL;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_NULL: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_CLIENTID(const SOCKET s, unsigned int *RegistrationVersion, unsigned int *RegistrationAuthority, unsigned int *AccountNumber, unsigned int *RegistrationToken, unsigned char *PCName, unsigned char *PCUsername)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_CLIENTID: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 4) + (BNET_UNKSTR_LEN * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 4) + (BNET_UNKSTR_LEN * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CLIENTID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//RegistrationVersion
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RegistrationVersion;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//RegistrationAuthority
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RegistrationAuthority;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//AccountNumber
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *AccountNumber;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//RegistrationToken
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RegistrationToken;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//PCName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), PCName, strlen((const char*)PCName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//PCUsername
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), PCUsername, strlen((const char*)PCUsername));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_CLIENTID: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_CLIENTID(const SOCKET s, unsigned int *RegistrationVersion, unsigned int *RegistrationAuthority, unsigned int *AccountNumber, unsigned int *RegistrationToken)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_CLIENTID: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 4)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 4));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CLIENTID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//RegistrationVersion
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RegistrationVersion;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//RegistrationAuthority
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RegistrationAuthority;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//AccountNumber
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *AccountNumber;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//RegistrationToken
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RegistrationToken;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_CLIENTID: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_STARTVERSIONING(const SOCKET s, unsigned char *PlatformID, unsigned int *version_byte, unsigned int *Unknowen)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_STARTVERSIONING: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 4)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 4));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_STARTVERSIONING;
	//Packet length can be hard coded since we know the entire size
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//PlatformID (IX86, PMAC, XMAC)
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *(unsigned int*)(PlatformID);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ProductID (JSTR, W2BN) 
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *(unsigned int*)(PlatformID + DW_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Product Version Byte (DWORD)
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *version_byte;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Unknowen DWORD
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Unknowen;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_STARTVERSIONING: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_STARTVERSIONING(const SOCKET s, unsigned char *FileTimeStr, unsigned char *MPQFileName, unsigned char *CheckFormula)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_STARTVERSIONING: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2) + (BNET_UNKSTR_LEN * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2) + (BNET_UNKSTR_LEN * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_STARTVERSIONING;
	//Packet length can be hard coded since we know the entire size
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//FileTimeStr 0-3
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *(unsigned int*)(FileTimeStr);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//FileTimeStr 4-7 
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *(unsigned int*)(FileTimeStr + DW_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//MPQFileName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), MPQFileName, strlen((const char*)MPQFileName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//CheckFormula
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), CheckFormula, strlen((const char*)CheckFormula));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_STARTVERSIONING: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_REPORTVERSION(const SOCKET s, unsigned char *PlatformID, unsigned int *version_byte,
	unsigned int *GameVersion, unsigned int *Checksum, unsigned char *ExeInfoString, unsigned int *InfoLength)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_REPORTVERSION: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 5) + BNET_UNKSTR_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 5) + BNET_UNKSTR_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_REPORTVERSION;
	//Packet length can be hard coded since we know the entire size
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//PlatformID (IX86, PMAC, XMAC)
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *(unsigned int*)(PlatformID);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ProductID (JSTR, DRTL, W2BN) 
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *(unsigned int*)(PlatformID + DW_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Product Version Byte (DWORD)
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *version_byte;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Game Exe Version
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *GameVersion;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Checksum
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Checksum;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Exe info string
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), ExeInfoString, *InfoLength);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += *InfoLength + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_REPORTVERSION: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_REPORTVERSION(const SOCKET s, unsigned int *Result, unsigned char *FilePath)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_REPORTVERSION: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_REPORTVERSION;
	//Packet length can be hard coded since we know the entire size
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Exe info string
	if (strlen((const char*)FilePath) >= BNET_FILEPATH_MAX)
	{
		FilePath[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), FilePath, strlen((const char*)FilePath));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_REPORTVERSION: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_GETADVLISTEX(const SOCKET s, unsigned int *GameType, unsigned int *GameSubType,
	unsigned int *Filter, unsigned int *Reserved, unsigned int *Count,
	unsigned char *GameName, unsigned char *GamePassword, unsigned char *GameStatstring)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_GETADVLISTEX: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (SW_LEN * 2) + (DW_LEN * 3) + BNET_GAMENAME_MAX + BNET_UNKSTR_LEN + BNET_STATSTRING_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (SW_LEN * 2) + (DW_LEN * 3) + BNET_GAMENAME_MAX + BNET_UNKSTR_LEN + BNET_STATSTRING_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_ENTERCHAT;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//GameType
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)*GameType;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;
	//GameSubType
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)*GameSubType;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;
	//Filter
	*(unsigned int*)(packet_buffer + BNET_LEN_POS) = *Filter;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Reserved
	*(unsigned int*)(packet_buffer + BNET_LEN_POS) = *Reserved;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Count
	*(unsigned int*)(packet_buffer + BNET_LEN_POS) = *Count;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//GameName
	if (strlen((const char*)GameName) >= BNET_GAMENAME_MAX)
	{
		GameName[BNET_GAMENAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GameName, strlen((const char*)GameName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//GamePassword
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GamePassword, strlen((const char*)GamePassword));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//GameStatstring
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GameStatstring, strlen((const char*)GameStatstring));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_GETADVLISTEX: HAS BEEN SENT\r\n");
#endif
}

struct GameListData
{
	unsigned short GameType = 0;
	unsigned short SubType = 0;
	unsigned int LanguageID = 0;
	unsigned short AddressFamily = 0;
	unsigned short Port = 0;
	unsigned int HostIP = 0;
	unsigned int Unk1 = 0;
	unsigned int Unk2 = 0;
	unsigned int GameStatus = 0;
	unsigned int ElapsedTime = 0;
	unsigned char *GameName;
	unsigned char *GamePasssword;
	unsigned char *GameStatstring;
};

void VB6_API2 SERVER_SID_GETADVLISTEX(const SOCKET s, unsigned int *NumberOfGames, unsigned int *Status,
	GameListData GameList[])
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_GETADVLISTEX: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[8196];
	ZeroMemory(packet_buffer, 8196);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_ENTERCHAT;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//NumberOfGames
	*(unsigned int*)(packet_buffer + BNET_LEN_POS) = *NumberOfGames;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	if (NumberOfGames == 0)
	{
		//Status
		*(unsigned int*)(packet_buffer + BNET_LEN_POS) = *Status;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	} else {
		for (unsigned int i = 0; i < *NumberOfGames; i++)
		{
			//GameType
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) = GameList[i].GameType;
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;
			//SubType
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) = GameList[i].SubType;
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;
			//LanguageID
			*(unsigned int*)(packet_buffer + BNET_LEN_POS) = GameList[i].LanguageID;
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
			//AddressFamily
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) = GameList[i].AddressFamily;
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;
			//Port
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) = GameList[i].Port;
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;
			//HostIP
			*(unsigned int*)(packet_buffer + BNET_LEN_POS) = GameList[i].HostIP;
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
			//Unk1
			*(unsigned int*)(packet_buffer + BNET_LEN_POS) = GameList[i].Unk1;
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
			//Unk2
			*(unsigned int*)(packet_buffer + BNET_LEN_POS) = GameList[i].Unk2;
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
			//GameStatus
			*(unsigned int*)(packet_buffer + BNET_LEN_POS) = GameList[i].GameStatus;
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
			//ElapsedTime
			*(unsigned int*)(packet_buffer + BNET_LEN_POS) = GameList[i].ElapsedTime;
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
			//GameName
			memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GameList[i].GameName, strlen((const char*)GameList[i].GameName));
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
			//GamePassword
			memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GameList[i].GamePasssword, strlen((const char*)GameList[i].GamePasssword));
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
			//GameStatstring
			memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GameList[i].GameStatstring, strlen((const char*)GameList[i].GameStatstring));
			*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
		}
	}

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_GETADVLISTEX: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_ENTERCHAT(const SOCKET s, unsigned char *Username, unsigned char *Statstring)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_ENTERCHAT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + BNET_USERNAME_MAX + BNET_STATSTRING_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + BNET_USERNAME_MAX + BNET_STATSTRING_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_ENTERCHAT;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Username
	if (strlen((const char*)Username) >= BNET_USERNAME_MAX)
	{
		Username[BNET_USERNAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Username, strlen((const char*)Username));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	//Statstring
	if (strlen((const char*)Statstring) >= BNET_STATSTRING_MAX)
	{
		Statstring[BNET_STATSTRING_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Statstring, strlen((const char*)Statstring));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_ENTERCHAT: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_ENTERCHAT(const SOCKET s, unsigned char *UniqueUsername, unsigned char *Statstring, unsigned char *Username)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_ENTERCHAT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + BNET_USERNAME_MAX + BNET_STATSTRING_MAX + BNET_USERNAME_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + BNET_USERNAME_MAX + BNET_STATSTRING_MAX + BNET_USERNAME_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_ENTERCHAT;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//UniqueUsername
	if (strlen((const char*)UniqueUsername) >= BNET_USERNAME_MAX)
	{
		UniqueUsername[BNET_USERNAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), UniqueUsername, strlen((const char*)UniqueUsername));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	//Statstring
	if (strlen((const char*)Statstring) >= BNET_STATSTRING_MAX)
	{
		Statstring[BNET_STATSTRING_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Statstring, strlen((const char*)Statstring));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	//Username
	if (strlen((const char*)Username) >= BNET_USERNAME_MAX)
	{
		Username[BNET_USERNAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Username, strlen((const char*)Username));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_ENTERCHAT: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_GETCHANNELLIST(const SOCKET s, unsigned char *ProductID)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_GETCHANNELLIST: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_GETCHANNELLIST;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ProductID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *(unsigned int*)(ProductID);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_GETCHANNELLIST: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_GETCHANNELLIST(const SOCKET s, unsigned int *NumberOfChannels, LPSAFEARRAY* Channels)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_GETCHANNELLIST: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	unsigned char packet_buffer[8196];
	ZeroMemory(packet_buffer, 8196);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_GETCHANNELLIST;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	char** StrPtr = 0; //this is how we access a string array sent from VB6
	SafeArrayAccessData(*Channels, reinterpret_cast<void**>(&StrPtr));
	for (unsigned int i = 0; i < *NumberOfChannels; i++)
	{
		//Channels[i]
		if (strlen(StrPtr[i]) >= BNET_CHANNELNAME_MAX) { StrPtr[i][BNET_CHANNELNAME_MAX] = 0x00; }
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), (unsigned char *)StrPtr[i], strlen((const char*)(StrPtr[i])));
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	}
	memcpy(StrPtr[0], "As Mother fuckin df", 20);
	SafeArrayUnaccessData(*Channels);

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_GETCHANNELLIST: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_JOINCHANNEL(const SOCKET s, unsigned int *Flags, unsigned char *ChannelName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_JOINCHANNEL: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN + BNET_CHANNELNAME_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN + BNET_CHANNELNAME_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_JOINCHANNEL;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Flags
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Flags;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//ChannelName
	if (strlen((const char*)ChannelName) >= BNET_CHANNELNAME_MAX)
	{
		ChannelName[BNET_CHANNELNAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), ChannelName, strlen((const char*)ChannelName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_JOINCHANNEL: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_CHATCOMMAND(const SOCKET s, unsigned char *TextMessage)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_CHATCOMMAND: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	unsigned char packet_buffer[BNET_HEAD_LEN + BNET_CMESSAGE_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + BNET_CMESSAGE_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CHATCOMMAND;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//TextMessage
	if (strlen((const char*)TextMessage) >= BNET_CMESSAGE_MAX)
	{
		TextMessage[BNET_CMESSAGE_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), TextMessage, strlen((const char*)TextMessage));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_CHATCOMMAND: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_CHATEVENT(const SOCKET s, unsigned int *EventID, unsigned int *UserFlags, unsigned int *PingTime, unsigned int *ServerIP, unsigned int *AccountNumber, unsigned int *RegistrationAuthority, unsigned char *Username, unsigned char *Message)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_CHATEVENT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 6) + BNET_USERNAME_MAX + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 6) + BNET_USERNAME_MAX + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CHATEVENT;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//EventID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *EventID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//UserFlags
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UserFlags;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//PingTime
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *PingTime;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ServerIP
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ServerIP;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//AccountNumber
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *AccountNumber;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//RegistrationAuthority
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RegistrationAuthority;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//UniqueUsername
	if (strlen((const char*)Username) >= BNET_USERNAME_MAX)
	{
		Username[BNET_USERNAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Username, strlen((const char*)Username));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//UniqueUsername
	if (strlen((const char*)Message) >= BNET_FILEPATH_MAX)
	{
		Message[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Message, strlen((const char*)Message));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_CHATEVENT: HAS BEEN SENT\r\n");
#endif

}

void VB6_API2 SID_LEAVECHAT(const SOCKET s)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_LEAVECHAT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_LEAVECHAT;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_LEAVECHAT: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_LOCALEINFO(const SOCKET s, const char *AbrevLangName, const char *CountryCode, const char *AbrevCountryName, const char *CountryName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_LOCALEINFO: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 8) + (BNET_UNKSTR_LEN * 4)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 8) + (BNET_UNKSTR_LEN * 4));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_LOCALEINFO;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	FILETIME sys, loc;
	//SystemTime ft
	sys = SystemTimeFT();
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = sys.dwLowDateTime;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = sys.dwHighDateTime;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//LocalTime ft
	loc = LocalTimeFT();
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = loc.dwLowDateTime;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = loc.dwHighDateTime;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//TimeZoneBias
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = GetBias();
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//System LCID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = GetSystemDefaultLCID();
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//User LocalID (Default LCID)
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = GetUserDefaultLCID();
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//UserLanguage ID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = GetUserDefaultLangID();
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//Lang Abrev
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), AbrevLangName, strlen((const char*)AbrevLangName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//Country Code
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), CountryCode, strlen((const char*)CountryCode));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//Country Abrev
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), AbrevCountryName, strlen((const char*)AbrevCountryName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//Country Name
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), CountryName, strlen((const char*)CountryName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_LOCALEINFO: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_FLOODDETECTED(const SOCKET s)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_FLOODDETECTED: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_FLOODDETECTED;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_FLOODDETECTED: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_UDPPINGRESPONSE(const SOCKET s, const char *UDPKey)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_UDPPINGRESPONSE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_UDPPINGRESPONSE;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//UDP Code
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *(unsigned int*)(UDPKey);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_UDPPINGRESPONSE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_CHECKAD(const SOCKET s, unsigned int *PlatformID, unsigned int *ProductID, unsigned int *LastBannerID, unsigned int *CurrentTime)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_CHECKAD: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 4)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 4));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CHECKAD;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//PlatformID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *PlatformID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ProductID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ProductID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//LastBannerID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *LastBannerID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//CurrentTime
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *CurrentTime;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_CHECKAD: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_CHECKAD(const SOCKET s, unsigned int *AdID, unsigned int *FileExt, unsigned int *LocalFileTimeP1, unsigned int *LocalFileTimeP2, unsigned char *Filename, unsigned char *LinkURL)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_CHECKAD: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 4) + (BNET_FILEPATH_MAX * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 4) + (BNET_FILEPATH_MAX * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CHECKAD;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//PlatformID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *AdID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ProductID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *FileExt;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//LastBannerID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *LocalFileTimeP1;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//CurrentTime
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *LocalFileTimeP2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//UniqueUsername
	if (strlen((const char*)Filename) >= BNET_FILEPATH_MAX)
	{
		Filename[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Filename, strlen((const char*)Filename));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//UniqueUsername
	if (strlen((const char*)LinkURL) >= BNET_FILEPATH_MAX)
	{
		LinkURL[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), LinkURL, strlen((const char*)LinkURL));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_CHECKAD: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_CLICKAD(const SOCKET s, unsigned int *AdID, unsigned int *RequestType)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_CLICKAD: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CLICKAD;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//PlatformID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *AdID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ProductID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RequestType;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_CLICKAD: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_READMEMORY(const SOCKET s, unsigned int *RequestID, unsigned char *DataBlock, unsigned int *Length)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_READMEMORY: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[8196];
	ZeroMemory(packet_buffer, 8196);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_READMEMORY;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//RequestID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RequestID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//DataBlock
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), DataBlock, *Length);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += *Length + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_READMEMORY: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_READMEMORY(const SOCKET s, unsigned int *RequestID, unsigned int *DataBlockAddress, unsigned int *DataBlockLength)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_READMEMORY: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 3)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 3));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_READMEMORY;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//RequestID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RequestID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//DataBlockAddress
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *DataBlockAddress;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//DataBlockLength
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *DataBlockLength;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_READMEMORY: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_MESSAGEBOX(const SOCKET s, unsigned int *Style, unsigned char *Message, unsigned char *Caption)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_MESSAGEBOX: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[8196];
	ZeroMemory(packet_buffer, 8196);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_MESSAGEBOX;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Style
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Style;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Message
	if (strlen((const char*)Message) >= BNET_FILEPATH_MAX)
	{
		Message[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Message, strlen((const char *)Message));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//Caption
	if (strlen((const char*)Caption) >= BNET_FILEPATH_MAX)
	{
		Caption[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Caption, strlen((const char *)Caption));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_MESSAGEBOX: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_STARTADVEX2(const SOCKET s, unsigned int *Status, unsigned int *UnknownDW1, unsigned short *GameType, unsigned short *UnknowenSW, unsigned int *UnknownDW2, unsigned int *Port, unsigned char *GameName, unsigned char *GamePassword, unsigned char *GameStats)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_STARTADVEX2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 4) + (BNET_FILEPATH_MAX * 3)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 4) + (SW_LEN * 2) + (BNET_FILEPATH_MAX * 3));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_STARTADVEX2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Status
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Status;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//UnknownDW1
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UnknownDW1;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//GameType
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *GameType;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;
	//UnknowenSW
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UnknowenSW;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;
	//UnknownDW2
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UnknownDW2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Port
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Port;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//GameName
	if (strlen((const char*)GameName) >= BNET_FILEPATH_MAX)
	{
		GameName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GameName, strlen((const char*)GameName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//GamePassword
	if (strlen((const char*)GamePassword) >= BNET_FILEPATH_MAX)
	{
		GamePassword[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GamePassword, strlen((const char*)GamePassword));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//GameStats
	if (strlen((const char*)GameStats) >= BNET_FILEPATH_MAX)
	{
		GameStats[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GameStats, strlen((const char*)GameStats));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_STARTADVEX2: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_STARTADVEX2(const SOCKET s, unsigned int *Result)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_STARTADVEX2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_STARTADVEX2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_STARTADVEX2: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_GAMEDATAADDRESS(const SOCKET s, unsigned short *UnknowenSW, unsigned short *Port, unsigned int *IPAddress, unsigned int *UnknowenDW1, unsigned int *UnknowenDW2)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_GAMEDATAADDRESS: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (SW_LEN * 2) + (DW_LEN * 3));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_GAMEDATAADDRESS;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//UnknowenSW
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UnknowenSW;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;
	//Port
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Port;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;
	//IPAddress
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *IPAddress;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//UnknowenDW1
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UnknowenDW1;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//UnknowenDW2
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UnknowenDW2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_GAMEDATAADDRESS: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_STARTADVEX3(const SOCKET s, unsigned int *Status, unsigned int *Uptime, unsigned short *GameType, unsigned short *SubGameType, unsigned int *ProviderVersion, unsigned int *LadderType, unsigned char *GameName, unsigned char *GamePassword, unsigned char *GameStats)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_STARTADVEX3: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 4) + (BNET_FILEPATH_MAX * 3)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 4) + (SW_LEN * 2) + (BNET_FILEPATH_MAX * 3));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_STARTADVEX3;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Status
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Status;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Uptime
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Uptime;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//GameType
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *GameType;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;
	//SubGameType
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *SubGameType;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;
	//ProviderVersion
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ProviderVersion;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//LadderType
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *LadderType;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//GameName
	if (strlen((const char*)GameName) >= BNET_FILEPATH_MAX)
	{
		GameName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GameName, strlen((const char*)GameName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//GamePassword
	if (strlen((const char*)GamePassword) >= BNET_FILEPATH_MAX)
	{
		GamePassword[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GamePassword, strlen((const char*)GamePassword));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//GameStats
	if (strlen((const char*)GameStats) >= BNET_FILEPATH_MAX)
	{
		GameStats[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GameStats, strlen((const char*)GameStats));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_STARTADVEX3: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_STARTADVEX3(const SOCKET s, unsigned int *Result)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_STARTADVEX3: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_STARTADVEX3;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Status
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_STARTADVEX3: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_LOGONCHALLENGEEX(const SOCKET s, unsigned int *UDPKey, unsigned int *ServerKey)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_LOGONCHALLENGEEX: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_LOGONCHALLENGEEX;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Status
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UDPKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Status
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ServerKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_LOGONCHALLENGEEX: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_CLIENTID2(const SOCKET s, unsigned int *ServerVersion, unsigned int *RegistrationVersion, unsigned int *RegistrationAuthority, unsigned int *AccountNumber, unsigned int *RegistrationToken, unsigned char *PCName, unsigned char *PCUsername)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_CLIENTID2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	if (*ServerVersion > 1) { return; }

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 5) + (BNET_UNKSTR_LEN * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 5) + (BNET_UNKSTR_LEN * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CLIENTID2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ServerVersion
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ServerVersion;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	switch (*ServerVersion)
	{
	case 0:
		//RegistrationAuthority
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RegistrationAuthority;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		//RegistrationVersion
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RegistrationVersion;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		break;
	case 1:
		//RegistrationVersion
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RegistrationVersion;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		//RegistrationAuthority
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RegistrationAuthority;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		break;
	}

	//AccountNumber
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *AccountNumber;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//RegistrationToken
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RegistrationToken;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//PCName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), PCName, strlen((const char*)PCName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//PCUsername
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), PCUsername, strlen((const char*)PCUsername));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_CLIENTID2: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_LEAVEGAME(const SOCKET s)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_LEAVEGAME: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_LEAVEGAME;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_LEAVEGAME: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_ANNOUNCEMENT(const SOCKET s, unsigned char *Message)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_ANNOUNCEMENT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_ANNOUNCEMENT;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Message
	if (strlen((const char *)Message) >= BNET_FILEPATH_MAX) {
		Message[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Message, strlen((const char *)Message));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((const char *)(packet_buffer + BNET_LEN_POS)) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_ANNOUNCEMENT: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_DISPLAYAD(const SOCKET s, unsigned int *PlatformID, unsigned int *ProductID, unsigned int *AdID, unsigned char *Filename, unsigned char *LinkURL)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_DISPLAYAD: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 4) + (BNET_FILEPATH_MAX * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 4) + (BNET_FILEPATH_MAX * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_DISPLAYAD;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//PlatformID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *PlatformID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ProductID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ProductID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//LastBannerID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *AdID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Filename
	if (strlen((const char*)Filename) >= BNET_FILEPATH_MAX)
	{
		Filename[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Filename, strlen((const char*)Filename));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//LinkURL
	if (strlen((const char*)LinkURL) >= BNET_FILEPATH_MAX)
	{
		LinkURL[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), LinkURL, strlen((const char*)LinkURL));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_DISPLAYAD: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_NOTIFYJOIN(const SOCKET s, unsigned int *ProductID, unsigned int *ProductVersion, unsigned char *GameName, unsigned char *GamePassword)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_NOTIFYJOIN: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_NOTIFYJOIN;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ProductID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ProductID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ProductVersion
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ProductVersion;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//GameName
	if (strlen((const char*)GameName) >= BNET_FILEPATH_MAX)
	{
		GameName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GameName, strlen((const char*)GameName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//GamePassword
	if (strlen((const char*)GamePassword) >= BNET_FILEPATH_MAX)
	{
		GamePassword[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), GamePassword, strlen((const char*)GamePassword));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_NOTIFYJOIN: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_WRITECOOKIE(const SOCKET s, unsigned int *UnknowenDW1, unsigned int *UnknowenDW2, unsigned char *KeyName, unsigned char *KeyValue)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_WRITECOOKIE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_WRITECOOKIE;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//UnknowenDW1
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UnknowenDW1;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//UnknowenDW2
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UnknowenDW2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//KeyName
	if (strlen((const char*)KeyName) >= BNET_FILEPATH_MAX)
	{
		KeyName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), KeyName, strlen((const char*)KeyName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//KeyValue
	if (strlen((const char*)KeyValue) >= BNET_FILEPATH_MAX)
	{
		KeyValue[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), KeyValue, strlen((const char*)KeyValue));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_WRITECOOKIE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_READCOOKIE(const SOCKET s, unsigned int *UnknowenDW1, unsigned int *UnknowenDW2, unsigned char *KeyName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_READCOOKIE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_READCOOKIE;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//UnknowenDW1
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UnknowenDW1;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//UnknowenDW2
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UnknowenDW2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//KeyName
	if (strlen((const char*)KeyName) >= BNET_FILEPATH_MAX)
	{
		KeyName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), KeyName, strlen((const char*)KeyName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_READCOOKIE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_READCOOKIE(const SOCKET s, unsigned int *StoC_UnknowenDW1, unsigned int *StoC_UnknowenDW2, unsigned char *KeyName, unsigned char *KeyValue)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_READCOOKIE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_READCOOKIE;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//StoC_UnknowenDW1
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *StoC_UnknowenDW1;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//StoC_UnknowenDW2
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *StoC_UnknowenDW2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//KeyName
	if (strlen((const char*)KeyName) >= BNET_FILEPATH_MAX)
	{
		KeyName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), KeyName, strlen((const char*)KeyName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//KeyValue
	if (strlen((const char*)KeyValue) >= BNET_FILEPATH_MAX)
	{
		KeyValue[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), KeyValue, strlen((const char*)KeyValue));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_READCOOKIE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_PING(const SOCKET s, unsigned int *CurrentPingTime)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_PING: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_PING;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//CurrentPingTime
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *CurrentPingTime;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_PING: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_PING(const SOCKET s, unsigned int *CurrentPingTime)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_LEAVEGAME: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_PING;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//CurrentPingTime
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *CurrentPingTime;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_LEAVEGAME: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_READUSERDATA(const SOCKET s, unsigned int *NumberOfAccounts, unsigned int *NumberOfKeys, unsigned int *RequestID, unsigned char *Usernames, unsigned int *NameLength, unsigned char *DBKeys, unsigned int *KeyLength)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_READUSERDATA: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	if (*NameLength >= BNET_FILEPATH_MAX) { return; }
	if (*KeyLength >= BNET_FILEPATH_MAX) { return; }
	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 3) + (BNET_FILEPATH_MAX * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 3) + (BNET_FILEPATH_MAX * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_READUSERDATA;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//NumberOfAccounts
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *NumberOfAccounts;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//NumberOfKeys
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *NumberOfKeys;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//RequestID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RequestID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//Usernames NameLength
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Usernames, *NameLength);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += *NameLength;
	//DBKeys KeyLength
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), DBKeys, *KeyLength);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += *KeyLength;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_READUSERDATA: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_READUSERDATA(const SOCKET s, unsigned int *NumberOfAccounts, unsigned int *NumberOfKeys, unsigned int *RequestID, unsigned char *DBKeyValues[])
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_READUSERDATA: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 3) + (BNET_FILEPATH_MAX * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 3) + (BNET_FILEPATH_MAX * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_READUSERDATA;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//NumberOfAccounts
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *NumberOfAccounts;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//NumberOfKeys
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *NumberOfKeys;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//RequestID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RequestID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	for (unsigned int i = 0; i < *NumberOfKeys; i++)
	{
		//DBKeys
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), DBKeyValues[i], strlen((const char *)DBKeyValues[i]));
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((const char *)DBKeyValues[i]) + 1;
	}

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_READUSERDATA: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_WRITEUSERDATA(const SOCKET s, unsigned int *NumberOfAccounts, unsigned int *NumberOfKeys, unsigned char *Usernames, unsigned int *NameLength, unsigned char *DBKeys, unsigned int *KeyLength, unsigned char *Values, unsigned int *ValuesLength)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_WRITEUSERDATA: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	if (*NameLength >= BNET_FILEPATH_MAX) { return; }
	if (*KeyLength >= BNET_FILEPATH_MAX) { return; }
	if (*Values >= BNET_FILEPATH_MAX) { return; }

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 3)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 3));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_WRITEUSERDATA;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//NumberOfAccounts
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *NumberOfAccounts;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//NumberOfKeys
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *NumberOfKeys;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//Usernames NameLength
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Usernames, *NameLength);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += *NameLength;
	//DBKeys KeyLength
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), DBKeys, *KeyLength);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += *KeyLength;
	//Values ValuesLength
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Values, *ValuesLength);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += *ValuesLength;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_WRITEUSERDATA: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_LOGONCHALLENGE(const SOCKET s, unsigned int *ServerKey)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_LOGONCHALLENGE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_LOGONCHALLENGE;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ServerKey
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ServerKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_LOGONCHALLENGE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_LOGONRESPONSE(const SOCKET s, unsigned int *ClientKey, unsigned int *ServerKey, unsigned char *SHABuffer, unsigned char *UserName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_LOGONRESPONSE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2) + SHA_LEN + BNET_USERNAME_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2) + SHA_LEN + BNET_USERNAME_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_LOGONRESPONSE;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ClientKey
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ClientKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ServerKey
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ServerKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//SHABuffer
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), SHABuffer, SHA_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SHA_LEN;
	//UserName
	if (strlen((const char*)UserName) >= BNET_USERNAME_MAX)
	{
		UserName[BNET_USERNAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), UserName, strlen((const char*)UserName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_LOGONRESPONSE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_LOGONRESPONSE(const SOCKET s, unsigned int *Result)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_LOGONCHALLENGE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_LOGONRESPONSE;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_LOGONRESPONSE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_CREATEACCOUNT(const SOCKET s, unsigned int *Result)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_CREATEACCOUNT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CREATEACCOUNT;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_CREATEACCOUNT: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_CREATEACCOUNT(const SOCKET s, unsigned char *SHABuffer, unsigned char *UserName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_CREATEACCOUNT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + SHA_LEN + BNET_USERNAME_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + SHA_LEN + BNET_USERNAME_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CREATEACCOUNT;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//SHABuffer
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), SHABuffer, SHA_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SHA_LEN;
	//UserName
	if (strlen((const char*)UserName) >= BNET_USERNAME_MAX)
	{
		UserName[BNET_USERNAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), UserName, strlen((const char*)UserName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_CREATEACCOUNT: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_SYSTEMINFO(const SOCKET s, unsigned int *ProcessorCount, unsigned int *ProcessorArch, unsigned int *ProcessorLevel, unsigned int *ProcessorTiming, unsigned int *TotalPhusicalMemory, unsigned int *TotalPageFile, unsigned int *FreeDiskSpace)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_SYSTEMINFO: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 7)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 7));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_SYSTEMINFO;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ProcessorCount
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ProcessorCount;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ProcessorArch
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ProcessorArch;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ProcessorLevel
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ProcessorLevel;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ProcessorTiming
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ProcessorTiming;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//TotalPhusicalMemory
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *TotalPhusicalMemory;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//TotalPageFile
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *TotalPageFile;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//FreeDiskSpace
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *FreeDiskSpace;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_SYSTEMINFO: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_GAMERESULT(const SOCKET s, unsigned int *GameType, unsigned int *ResultCount8, unsigned int *Results[], unsigned char *Players[], unsigned char *MapName, unsigned char *PlayerScore)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_GAMERESULT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	if (*ResultCount8 != 8) { return; }

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 10) + (BNET_USERNAME_MAX * 8) + (BNET_FILEPATH_MAX * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 10) + (BNET_USERNAME_MAX * 8) + (BNET_FILEPATH_MAX * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_GAMERESULT;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//GameType
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *GameType;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ResultCount8
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ResultCount8;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Results[]
	for (unsigned int i = 0; i < *ResultCount8; i++)
	{
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Results[i];
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	}
	//Players[]
	for (unsigned int i = 0; i < *ResultCount8; i++)
	{
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Players[i], strlen((const char*)Players[i]));
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	}
	//MapName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), MapName, strlen((const char*)MapName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//PlayerScore
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), PlayerScore, strlen((const char*)PlayerScore));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_GAMERESULT: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_GETICONDATA(const SOCKET s)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_GETICONDATA: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_GETICONDATA;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_GETICONDATA: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_GETICONDATA(const SOCKET s, unsigned int *FT_P1, unsigned int *FT_P2, unsigned char *FileName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_GETICONDATA: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2) + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2) + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_GETICONDATA;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//FT_P1
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *FT_P1;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//FT_P2
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *FT_P2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//FileName
	if (strlen((const char *)FileName) >= BNET_FILEPATH_MAX)
	{
		FileName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), FileName, strlen((const char*)FileName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_GETICONDATA: HAS BEEN SENT\r\n");
#endif
}

struct LadderListing {
	unsigned int Wins;
	unsigned int Losses;
	unsigned int Disconnects;
	unsigned int Rating;
	unsigned int Rank;
	unsigned int OfficialWins;
	unsigned int OfficialLosses;
	unsigned int OfficialDisconnects;
	unsigned int OfficialRating;
	unsigned int Unknowen1;
	unsigned int OfficialRank;
	unsigned int Unknowen2;
	unsigned int Unknowen3;
	unsigned int HighestRating;
	unsigned int Unknowen4;
	unsigned int Season;
	unsigned int LastGameTimeFileTimePart1;
	unsigned int LastGameTimeFileTimePart2;
	unsigned int OfficialLastGameTimeFileTimePart1;
	unsigned int OfficialLastGameTimeFileTimePart2;
	unsigned char *Username;
};

void VB6_API2 SERVER_SID_GETLADDERDATA(const SOCKET s, unsigned int *ProductID, unsigned int *League, unsigned int *SortMethod, unsigned int *StartingRank, unsigned int *ListCount, LadderListing UserList[])
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_GETLADDERDATA: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	if (*ListCount > 10) { return; }

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 5) + ((sizeof(LadderListing) * 10) + (BNET_USERNAME_MAX * 10))];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 5) + ((sizeof(LadderListing) * 10) + (BNET_USERNAME_MAX * 10)));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_GETLADDERDATA;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ProductID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ProductID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//League
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *League;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//SortMethod
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *SortMethod;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//StartingRank
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *StartingRank;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ListCount
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ListCount;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Listing Data
	for (unsigned int i = 0; i < *ListCount; i++)
	{
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].Wins;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].Losses;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].Disconnects;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].Rating;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].Rank;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].OfficialWins;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].OfficialLosses;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].OfficialDisconnects;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].OfficialRating;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].Unknowen1;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].OfficialRank;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].Unknowen2;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].Unknowen3;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].HighestRating;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].Unknowen4;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].Season;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].LastGameTimeFileTimePart1;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].LastGameTimeFileTimePart2;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].OfficialLastGameTimeFileTimePart1;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = UserList[i].OfficialLastGameTimeFileTimePart2;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		//FileName
		if (strlen((const char *)UserList[i].Username) >= BNET_USERNAME_MAX)
		{
			UserList[i].Username[BNET_USERNAME_MAX] = 0x00;
		}
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), UserList[i].Username, strlen((const char*)UserList[i].Username));
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	}

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_GETLADDERDATA: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_GETLADDERDATA(const SOCKET s, unsigned int *ProductID, unsigned int *League, unsigned int *SortMethod, unsigned int *StartingRank, unsigned int *ListCount)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_GETLADDERDATA: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	if (*ListCount > 10) { return; }

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 5)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 5));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_GETLADDERDATA;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ProductID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ProductID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//League
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *League;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//SortMethod
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *SortMethod;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//StartingRank
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *StartingRank;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ListCount
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ListCount;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_GETLADDERDATA: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_FINDLADDERUSER(const SOCKET s, unsigned int *ProductID, unsigned int *League, unsigned int *SortMethod, unsigned char *UserName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_FINDLADDERUSER: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 3) + BNET_USERNAME_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 3) + BNET_USERNAME_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_FINDLADDERUSER;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ProductID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ProductID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//League
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *League;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//SortMethod
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *SortMethod;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//UserName
	if (strlen((const char*)UserName) >= BNET_USERNAME_MAX)
	{
		UserName[BNET_USERNAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), UserName, strlen((const char*)UserName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;


	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_FINDLADDERUSER: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_FINDLADDERUSER(const SOCKET s, unsigned int *Rank)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_FINDLADDERUSER: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_FINDLADDERUSER;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Rank
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Rank;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_FINDLADDERUSER: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_CDKEY(const SOCKET s, unsigned int *Spawn, unsigned char *CDKey, unsigned char *CDKeyOwner)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_CDKEY: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	if (strlen((const char*)CDKey) >= BNET_CDKEY_MAX) { return; } //Maximum length of a cdkey these days is 26 for starcraft

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN + BNET_CDKEY_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN + BNET_CDKEY_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CDKEY;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Product Version Byte (DWORD)
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Spawn;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//Username
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), CDKey, strlen((const char*)CDKey));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	//Statstring
	if (strlen((const char*)CDKeyOwner) >= BNET_CDKEYOWNER_MAX)
	{
		CDKeyOwner[BNET_CDKEYOWNER_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), CDKeyOwner, strlen((const char*)CDKeyOwner));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_CDKEY: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_CDKEY(const SOCKET s, unsigned int *Result, unsigned char *Message)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_CDKEY: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CDKEY;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Username
	if (strlen((const char*)Message) >= BNET_FILEPATH_MAX)
	{
		Message[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Message, strlen((const char*)Message));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_CDKEY: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_CHANGEPASSWORD(const SOCKET s, unsigned int *ClientKey, unsigned int *ServerKey, unsigned char *SHABufferOLD, unsigned char *SHABufferNew, unsigned char *AccountName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_CHANGEPASSWORD: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2) + (SHA_LEN * 2) + BNET_USERNAME_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2) + (SHA_LEN * 2) + BNET_USERNAME_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CHANGEPASSWORD;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ClientKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ServerKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//OLDPass buffer
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), SHABufferOLD, SHA_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SHA_LEN;
	//NEWPass buffer
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), SHABufferNew, SHA_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SHA_LEN;

	//Username
	if (strlen((const char*)AccountName) >= BNET_USERNAME_MAX)
	{
		AccountName[BNET_USERNAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), AccountName, strlen((const char*)AccountName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_CHANGEPASSWORD: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_CHANGEPASSWORD(const SOCKET s, unsigned int *Result)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_CHANGEPASSWORD: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CHANGEPASSWORD;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_CHANGEPASSWORD: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_GETFILETIME(const SOCKET s, unsigned int *RequestID, unsigned int *Unknowen, unsigned char *FileName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_GETFILETIME: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2) + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2) + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_GETFILETIME;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//RequestID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RequestID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Unknowen
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Unknowen;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//FileName
	if (strlen((const char*)FileName) >= BNET_FILEPATH_MAX)
	{
		FileName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), FileName, strlen((const char*)FileName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_GETFILETIME: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_GETFILETIME(const SOCKET s, unsigned int *RequestID, unsigned int *Unknowen, unsigned int *FT1, unsigned int *FT2, unsigned char *FileName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_GETFILETIME: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 4) + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 4) + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_GETFILETIME;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//RequestID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RequestID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Unknowen
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Unknowen;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//FT1
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *FT1;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//FT2
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *FT2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//FileName
	if (strlen((const char*)FileName) >= BNET_FILEPATH_MAX)
	{
		FileName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), FileName, strlen((const char*)FileName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_GETFILETIME: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_PROFILE(const SOCKET s, unsigned int *Cookie, unsigned char *UserName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_PROFILE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + 1 + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + 1 + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_PROFILE;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Cookie
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Cookie;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//UserName
	if(strlen((const char*)UserName) >= BNET_FILEPATH_MAX)
	{
		UserName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), UserName, strlen((const char*)UserName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_PROFILE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_PROFILE(const SOCKET s, unsigned int *Cookie, unsigned char status, unsigned char *Description, unsigned char *Location, unsigned int *ClanTag)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_PROFILE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + 1 + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + 1 + (DW_LEN * 2) + (BNET_FILEPATH_MAX * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_PROFILE;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Cookie
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Cookie;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//status
	*(unsigned char*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = status;
	*(unsigned char*)(packet_buffer + BNET_LEN_POS) += 1;

	if (status == 0)
	{
		//FileName
		if (strlen((const char*)Description) >= BNET_FILEPATH_MAX)
		{
			Description[BNET_FILEPATH_MAX] = 0x00;
		}
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Description, strlen((const char*)Description));
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
		//Description
		if (strlen((const char*)Location) >= BNET_FILEPATH_MAX)
		{
			Location[BNET_FILEPATH_MAX] = 0x00;
		}
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Location, strlen((const char*)Location));
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
		//ClanTag
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ClanTag;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	}

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_PROFILE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_CDKEY2(const SOCKET s, unsigned int *Spawn, unsigned int *CDKeyLength, unsigned int *CDKeyProductValue, unsigned int *CDKeyPublicValue, unsigned int *ServerKey, unsigned int *ClientKey, unsigned char *SHABuffer, unsigned char *CDKeyOwner)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_CDKEY: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 5) + SHA_LEN + BNET_CDKEY_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 5) + SHA_LEN + BNET_CDKEY_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CDKEY2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Spawn
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Spawn;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//CDKeyLength
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *CDKeyLength;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//CDKeyPublicValue
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *CDKeyPublicValue;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ServerKey
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ServerKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ClientKey
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ClientKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//SHABuffer
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), SHABuffer, SHA_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SHA_LEN;

	//Statstring
	if (strlen((const char*)CDKeyOwner) >= BNET_CDKEYOWNER_MAX)
	{
		CDKeyOwner[BNET_CDKEYOWNER_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), CDKeyOwner, strlen((const char*)CDKeyOwner));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_CDKEY: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_CDKEY2(const SOCKET s, unsigned int *Result, unsigned char *Message)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_CDKEY2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CDKEY2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Message
	if (strlen((const char*)Message) >= BNET_FILEPATH_MAX)
	{
		Message[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Message, strlen((const char*)Message));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_CDKEY2: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_LOGONRESPONSE2(const SOCKET s, unsigned int *ClientKey, unsigned int *ServerKey, unsigned char *HashData, unsigned char *Username)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_LOGONRESPONSE2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2) + SHA_LEN + BNET_USERNAME_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2) + SHA_LEN + BNET_USERNAME_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_LOGONRESPONSE2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ClientKey
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ClientKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//ServerKey
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ServerKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//HashData
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), HashData, 20);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SHA_LEN;
	//Username
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Username, strlen((const char*)Username));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_LOGONRESPONSE2: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_LOGONRESPONSE2(const SOCKET s, unsigned int *Result, unsigned char *Message)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_LOGONRESPONSE2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_LOGONRESPONSE2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Message
	if (strlen((const char*)Message) >= BNET_FILEPATH_MAX)
	{
		Message[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Message, strlen((const char*)Message));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_LOGONRESPONSE2: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_CHECKDATAFILE2(const SOCKET s, unsigned int *FileSizeInBytes, unsigned char *SHABuffer, unsigned char *FileName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_CHECKDATAFILE2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN + SHA_LEN + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN + SHA_LEN + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CHECKDATAFILE2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//FileSizeInBytes
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *FileSizeInBytes;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//SHABuffer
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), SHABuffer, SHA_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SHA_LEN;
	//FileName
	if (strlen((const char*)FileName) >= BNET_FILEPATH_MAX)
	{
		FileName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), FileName, strlen((const char*)FileName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_CHECKDATAFILE2: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_CHECKDATAFILE2(const SOCKET s, unsigned int *Result)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_CHECKDATAFILE2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CHECKDATAFILE2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_CHECKDATAFILE2: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_CREATEACCOUNT2(const SOCKET s, unsigned char *HashData, unsigned char *Username)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_CREATEACCOUNT2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + SHA_LEN + BNET_USERNAME_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + SHA_LEN + BNET_USERNAME_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CREATEACCOUNT2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//HashData
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), HashData, SHA_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SHA_LEN;
	//Username
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Username, strlen((const char*)Username));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_CREATEACCOUNT2: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_CREATEACCOUNT2(const SOCKET s, unsigned int *Result, unsigned char *Message)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_CREATEACCOUNT2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_CREATEACCOUNT2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Message
	if (strlen((const char*)Message) >= BNET_FILEPATH_MAX)
	{
		Message[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Message, strlen((const char*)Message));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_CREATEACCOUNT2: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_LOGONREALMEX(const SOCKET s, unsigned int *ClientKey, unsigned char *HashData, unsigned char *RealmName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_LOGONREALMEX: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN + SHA_LEN + BNET_USERNAME_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN + SHA_LEN + BNET_USERNAME_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_LOGONREALMEX;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ClientKey
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ClientKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//HashData
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), HashData, SHA_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SHA_LEN;
	//RealmName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), RealmName, strlen((const char*)RealmName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_LOGONREALMEX: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_LOGONREALMEX(const SOCKET s, unsigned int *Cookie, unsigned int *Status, unsigned char *Chunk1, unsigned int *IP, unsigned int *Port, unsigned char *Chunk2, unsigned char *UniqueAccountName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_LOGONREALMEX: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 4) + MCPC1_LEN + MCPC2_LEN + BNET_USERNAME_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 4) + MCPC1_LEN + MCPC2_LEN + BNET_USERNAME_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_LOGONREALMEX;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Cookie
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Cookie;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Status
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Status;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Chunk1
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Chunk1, MCPC1_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += MCPC1_LEN;
	//IP
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *IP;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Port
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Port;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Chunk2
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Chunk2, MCPC2_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += MCPC2_LEN;
	//UniqueAccountName
	if (strlen((const char *)UniqueAccountName) >= BNET_USERNAME_MAX)
	{
		UniqueAccountName[BNET_USERNAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), UniqueAccountName, strlen((const char*)UniqueAccountName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_LOGONREALMEX: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_QUERYREALMS2(const SOCKET s)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_QUERYREALMS2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_QUERYREALMS2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_QUERYREALMS2: HAS BEEN SENT\r\n");
#endif
}

struct RealmListing {
	unsigned int *Unknowen;
	unsigned char *RealmTitle;
	unsigned char *RealmDiscription;
};
void VB6_API2 SERVER_SID_QUERYREALMS2(const SOCKET s, unsigned int *Unknowen0, unsigned int *RealmCount, RealmListing *RealmList[])
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_QUERYREALMS2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	if (*RealmCount > 10 || *RealmCount == 0) { return; }

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 2) + ((DW_LEN * 10) + (BNET_FILEPATH_MAX * 20))];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 2) + ((DW_LEN * 10) + (BNET_FILEPATH_MAX * 20)));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_QUERYREALMS2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Unknowen0
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Unknowen0;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//RealmCount
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RealmCount;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Listing RealmList[i]
	for (unsigned int i = 0; i < *RealmCount; i++)
	{
		//RealmList[i]->Unknowen
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *RealmList[i]->Unknowen;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		//RealmList[i]->RealmTitle
		if (strlen((const char *)RealmList[i]->RealmTitle) >= BNET_FILEPATH_MAX)
		{
			RealmList[i]->RealmTitle[BNET_FILEPATH_MAX] = 0x00;
		}
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), RealmList[i]->RealmTitle, strlen((const char*)RealmList[i]->RealmTitle));
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
		//RealmList[i]->RealmDiscription
		if (strlen((const char *)RealmList[i]->RealmDiscription) >= BNET_FILEPATH_MAX)
		{
			RealmList[i]->RealmDiscription[BNET_FILEPATH_MAX] = 0x00;
		}
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), RealmList[i]->RealmDiscription, strlen((const char*)RealmList[i]->RealmDiscription));
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	}

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_QUERYREALMS2: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_QUERYADURL(const SOCKET s, unsigned int *AdID)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_QUERYADURL: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_QUERYADURL;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//AdID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *AdID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_QUERYADURL: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_QUERYADURL(const SOCKET s, unsigned int *AdID, unsigned char *LinkURL)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_QUERYADURL: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_QUERYADURL;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//AdID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *AdID;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//LinkURL
	if (strlen((const char *)LinkURL) >= BNET_FILEPATH_MAX)
	{
		LinkURL[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), LinkURL, strlen((const char*)LinkURL));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_QUERYADURL: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_NETGAMEPORT(const SOCKET s, unsigned short *Port)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_NETGAMEPORT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + SW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + SW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_NETGAMEPORT;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Port
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Port;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_NETGAMEPORT: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_NEWS_INFO(const SOCKET s, unsigned int *TimeStamp1970)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_NEWS_INFO: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_NEWS_INFO;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//AdID
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *TimeStamp1970;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_NEWS_INFO: HAS BEEN SENT\r\n");
#endif
}

struct NewsListing {
	unsigned int *Time1970;
	unsigned char *NewsMessage;
};
void VB6_API2 SERVER_SID_NEWS_INFO(const SOCKET s, unsigned char NumberOfEntrys, unsigned int *LastLoggedTimeStamp1970, unsigned int *OldestNewsTimeStamp1970, unsigned int *NewestNewsTimeStamp1970, NewsListing *NewsList[])
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_NEWS_INFO: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	if (NumberOfEntrys == 0) { return; }

	unsigned char packet_buffer[BNET_HEAD_LEN + 1 + (DW_LEN * 3) + ((DW_LEN * 255) + (BNET_FILEPATH_MAX * 255))];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_NEWS_INFO;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//NumberOfEntrys
	*(unsigned char*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = NumberOfEntrys;
	*(unsigned char*)(packet_buffer + BNET_LEN_POS) += 1;
	//LastLoggedTimeStamp1970
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *LastLoggedTimeStamp1970;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//OldestNewsTimeStamp1970
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *OldestNewsTimeStamp1970;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//NewestNewsTimeStamp1970
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *NewestNewsTimeStamp1970;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//NewsList[i]
	for (unsigned int i = 0; i < NumberOfEntrys; i++)
	{
		//LastLoggedTimeStamp1970
		*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *NewsList[i]->Time1970;
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
		//LinkURL
		if (strlen((const char *)NewsList[i]->NewsMessage) >= BNET_FILEPATH_MAX)
		{
			NewsList[i]->NewsMessage[BNET_FILEPATH_MAX] = 0x00;
		}
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), NewsList[i]->NewsMessage, strlen((const char*)NewsList[i]->NewsMessage));
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	}

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_NEWS_INFO: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_OPTIONALWORK(const SOCKET s, unsigned char *FileName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_OPTIONALWORK: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_OPTIONALWORK;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//FileName
	if (strlen((const char *)FileName) >= BNET_FILEPATH_MAX)
	{
		FileName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), FileName, strlen((const char*)FileName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_OPTIONALWORK: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_EXTRAWORK(const SOCKET s, unsigned short *DataLength, unsigned char *MemoryMessage)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_EXTRAWORK: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	if (*DataLength > BNET_MEMORYBLOCK_LEN) { return; }

	unsigned char packet_buffer[BNET_HEAD_LEN + SW_LEN + BNET_MEMORYBLOCK_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + SW_LEN + BNET_MEMORYBLOCK_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_EXTRAWORK;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//DataLength
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *DataLength;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SW_LEN;

	//SID_EXTRAWORK
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), MemoryMessage, *DataLength);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += *DataLength;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_EXTRAWORK: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_REQUIREDWORK(const SOCKET s, unsigned char *FileName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_REQUIREDWORK: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_REQUIREDWORK;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;
	
	//FileName
	if (strlen((const char *)FileName) >= BNET_FILEPATH_MAX)
	{
		FileName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), FileName, strlen((const char*)FileName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_REQUIREDWORK: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_AUTHINFO(const SOCKET s, unsigned char *PlatformID, unsigned int *version_byte, unsigned char *LangCode, unsigned int *LocalIP, unsigned char *CountryAbreviation, unsigned char *CountryName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_AUTHINFO: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)


	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 9) + (BNET_UNKSTR_LEN * 2)];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 9) + (BNET_UNKSTR_LEN * 2));

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_AUTHINFO;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ProtocolID has always been 0x00000000
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = 0;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//PlatformID (IX86, PMAC, XMAC)
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *(unsigned int*)(PlatformID);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//ProductID (STAR, SEXP, W2BN, D2DV, D2XP, etc.) 
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *(unsigned int*)(PlatformID + 4);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//Product Version Byte (DWORD)
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *version_byte;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//Language Code enUS
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *(unsigned int*)(LangCode);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//LocalIP (NAT Capabilitys)
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *LocalIP;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//TimeZoneBias
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = GetBias();
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//LocalID (Default LCID)
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = GetUserDefaultLCID();
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//LanguageID (DefaultLang)
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = GetUserDefaultLangID();
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//Country Abbreviation Code
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), CountryAbreviation, strlen((const char*)CountryAbreviation));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	//Country
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), CountryName, strlen((const char*)CountryName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_AUTHINFO: HAS BEEN SENT\r\n");
#endif

}

void VB6_API2 SERVER_SID_AUTHINFO(const SOCKET s, unsigned int *LoginVersion, unsigned int *ServerKey, unsigned int *UDPKey, unsigned int *MPQFT_P1, unsigned int *MPQFT_P2, unsigned char *MPQFileName, unsigned char *Formula, unsigned char *ServerSignature)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_AUTHINFO: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)


	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 5) + (BNET_FILEPATH_MAX * 2) + NLS_SIGNATURE_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 5) + (BNET_FILEPATH_MAX * 2) + NLS_SIGNATURE_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_AUTHINFO;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//LoginVersion
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *LoginVersion;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//ServerKey
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ServerKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//UDPKey
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *UDPKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//MPQFT_P1
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *MPQFT_P1;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//MPQFT_P2
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *MPQFT_P2;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	//MPQFileName
	if (strlen((const char *)MPQFileName) >= BNET_FILEPATH_MAX)
	{
		MPQFileName[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), MPQFileName, strlen((const char*)MPQFileName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;
	//Formula
	if (strlen((const char *)Formula) >= BNET_FILEPATH_MAX)
	{
		Formula[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Formula, strlen((const char*)Formula));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	//ServerSignature
	if (*LoginVersion > 0) {
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), ServerSignature, NLS_SIGNATURE_LEN);
		*(unsigned short*)(packet_buffer + BNET_LEN_POS) += NLS_SIGNATURE_LEN;
	}

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_AUTHINFO: HAS BEEN SENT\r\n");
#endif

}

void VB6_API2 SID_AUTH_CHECK(const SOCKET s, unsigned int *ClientKey,
	unsigned int *GameVersion, unsigned int *Checksum,
	unsigned int *NumberOfKeys, unsigned int *Spawn,
	unsigned char *HashData, unsigned char *Exeinfo,
	unsigned int *InfoLength, unsigned char *CDKeyOwner)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_AUTH_CHECK: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (DW_LEN * 5) + (KEY_HASH_LEN * 2) + BNET_UNKSTR_LEN + BNET_CDKEYOWNER_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (DW_LEN * 5) + (KEY_HASH_LEN * 2) + BNET_UNKSTR_LEN + BNET_CDKEYOWNER_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_AUTH_CHECK;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ClientKey
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *ClientKey;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//GameVersion
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *GameVersion;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Checksum
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Checksum;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//NumberOfKeys
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *NumberOfKeys;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Spawn
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Spawn;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//HashData (All of the data including key type pub etc etc.)
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), HashData, (KEY_HASH_LEN * (*NumberOfKeys)));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += (KEY_HASH_LEN * (*NumberOfKeys));
	//Exeinfo InfoLength
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Exeinfo, *InfoLength);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += *InfoLength + 1;
	//CDKeyOwner
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), CDKeyOwner, strlen((const char*)CDKeyOwner));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_AUTH_CHECK: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_AUTH_CHECK(const SOCKET s, unsigned int *Result, unsigned char *Message)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_AUTH_CHECK: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_AUTH_CHECK;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Message
	if (strlen((const char*)Message) >= BNET_FILEPATH_MAX)
	{
		Message[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Message, strlen((const char*)Message));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_AUTH_CHECK: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_AUTH_ACCOUNTCREATE(const SOCKET s, unsigned char *Salt, unsigned char *Verifier, unsigned char *UserName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_AUTH_ACCOUNTCREATE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (NLS_SALT_LEN * 2) + BNET_USERNAME_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (NLS_SALT_LEN * 2) + BNET_USERNAME_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_AUTH_ACCOUNTCREATE;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Salt
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Salt, NLS_SALT_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += NLS_SALT_LEN;
	//Verifier
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Verifier, NLS_SALT_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += NLS_SALT_LEN;
	//Message
	if (strlen((const char*)UserName) >= BNET_USERNAME_MAX)
	{
		UserName[BNET_USERNAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), UserName, strlen((const char*)UserName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_AUTH_ACCOUNTCREATE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_AUTH_ACCOUNTCREATE(const SOCKET s, unsigned int *Result)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_AUTH_ACCOUNTCREATE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_AUTH_ACCOUNTCREATE;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_AUTH_ACCOUNTCREATE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_AUTH_ACCOUNTLOGON(const SOCKET s, unsigned char *Client_A, unsigned char *UserName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_AUTH_ACCOUNTLOGON: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + NLS_SALT_LEN + BNET_USERNAME_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + NLS_SALT_LEN + BNET_USERNAME_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_AUTH_ACCOUNTLOGON;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Client_A
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Client_A, NLS_SALT_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += NLS_SALT_LEN;
	//Message
	if (strlen((const char*)UserName) >= BNET_USERNAME_MAX)
	{
		UserName[BNET_USERNAME_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), UserName, strlen((const char*)UserName));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_AUTH_ACCOUNTLOGON: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_AUTH_ACCOUNTLOGON(const SOCKET s, unsigned int *Result, unsigned char *Salt_S, unsigned char *ServerKey_B)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_AUTH_ACCOUNTLOGON: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + (NLS_SALT_LEN * 2) + DW_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + (NLS_SALT_LEN * 2) + DW_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_AUTH_ACCOUNTLOGON;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//Salt_S
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Salt_S, NLS_SALT_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += NLS_SALT_LEN;
	//ServerKey_B
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), ServerKey_B, NLS_SALT_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += NLS_SALT_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_AUTH_ACCOUNTLOGON: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SID_AUTH_ACCOUNTLOGONPROOF(const SOCKET s, unsigned char *M1)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SID_AUTH_ACCOUNTLOGONPROOF: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + SHA_LEN];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + SHA_LEN);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_AUTH_ACCOUNTLOGONPROOF;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//ServerKey_B
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), M1, SHA_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SHA_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SID_AUTH_ACCOUNTLOGONPROOF: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 SERVER_SID_AUTH_ACCOUNTLOGONPROOF(const SOCKET s, unsigned int *Result, unsigned char *M2, unsigned char *Message)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("SERVER_SID_AUTH_ACCOUNTLOGONPROOF: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BNET_HEAD_LEN + DW_LEN + SHA_LEN + BNET_FILEPATH_MAX];
	ZeroMemory(packet_buffer, BNET_HEAD_LEN + DW_LEN + SHA_LEN + BNET_FILEPATH_MAX);

	*(packet_buffer + 0) = BNET_PROTO;
	*(packet_buffer + 1) = ID_SID_AUTH_ACCOUNTLOGONPROOF;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) = (unsigned short)BNET_HEAD_LEN;

	//Result
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))) = *Result;
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += DW_LEN;
	//M2
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), M2, SHA_LEN);
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += SHA_LEN;
	//Message
	if (strlen((const char*)Message) >= BNET_FILEPATH_MAX)
	{
		Message[BNET_FILEPATH_MAX] = 0x00;
	}
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS))), Message, strlen((const char*)Message));
	*(unsigned short*)(packet_buffer + BNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BNET_LEN_POS)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("SERVER_SID_AUTH_ACCOUNTLOGONPROOF: HAS BEEN SENT\r\n");
#endif
}

#pragma endregion

#pragma region "MCP PACKET LISTING"

void VB6_API2 MCP_INIT(const SOCKET s)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_INIT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)
	unsigned char packet_buffer[1];
	ZeroMemory(packet_buffer, 1);
	packet_buffer[0] = 0x1;
	send(s, (const char *)packet_buffer, 1, 0);

}

void VB6_API2 MCP_STARTUP(const SOCKET s, unsigned char *Cookie, unsigned char *Status, unsigned char *Chunk1, unsigned char *Chunk2, unsigned char *UnkName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_STARTUP: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[128];
	ZeroMemory(packet_buffer, 128);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_STARTUP;

	//Cookie
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *(unsigned int*)(Cookie);
	*(unsigned short*)(packet_buffer + 0) += 4;
	//Status
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *(unsigned int*)(Status);
	*(unsigned short*)(packet_buffer + 0) += 4;
	//Chunk1
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), Chunk1, 8);
	*(unsigned short*)(packet_buffer + 0) += 8;
	//Chunk2
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), Chunk2, 48);
	*(unsigned short*)(packet_buffer + 0) += 48;
	//UnkName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), UnkName, strlen((const char*)UnkName));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;


	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_STARTUP: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_CHARCREATE(const SOCKET s, unsigned int *CharClass, unsigned int *CharMask, unsigned char *CharName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_CHARCREATE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[128];
	ZeroMemory(packet_buffer, 128);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_CHARCREATE;

	//CharClass
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *CharClass;
	*(unsigned short*)(packet_buffer + 0) += 4;
	//CharMask
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *(unsigned short*)(CharMask);
	*(unsigned short*)(packet_buffer + 0) += 2;
	//CharName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), CharName, strlen((const char*)CharName));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;


	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_CHARCREATE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_CREATEGAME(const SOCKET s, unsigned int *RequestID, unsigned int *Difficulty,
	unsigned char *Unk_1, unsigned char *LevelRestriction, unsigned char *MaximumPlayers,
	unsigned char *GameName, unsigned char *GamePassword, unsigned char *GameDiscription)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_CREATEGAME: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[2048];
	ZeroMemory(packet_buffer, 2048);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_CREATEGAME;

	//RequestID
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *(unsigned short*)(RequestID);
	*(unsigned short*)(packet_buffer + 0) += 2;
	//Difficulty
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *Difficulty;
	*(unsigned short*)(packet_buffer + 0) += 4;
	//Unk_1
	*(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = (Unk_1[0]);
	*(unsigned short*)(packet_buffer + 0) += 1;
	//LevelRestriction
	*(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = (LevelRestriction[0]);
	*(unsigned short*)(packet_buffer + 0) += 1;
	//MaximumPlayers
	*(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = (MaximumPlayers[0]);
	*(unsigned short*)(packet_buffer + 0) += 1;
	//GameName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), GameName, strlen((const char*)GameName));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
	//GamePassword
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), GamePassword, strlen((const char*)GamePassword));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
	//GameDiscription
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), GameDiscription, strlen((const char*)GameDiscription));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;


	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_CREATEGAME: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_JOINGAME(const SOCKET s, unsigned int *RequestID, unsigned char *GameName, unsigned char *GamePassword)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_JOINGAME: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[512];
	ZeroMemory(packet_buffer, 512);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_JOINGAME;

	//RequestID
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *(unsigned short*)(RequestID);
	*(unsigned short*)(packet_buffer + 0) += 2;
	//GameName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), GameName, strlen((const char*)GameName));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
	//GamePassword
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), GamePassword, strlen((const char*)GamePassword));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;


	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_JOINGAME: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_GAMELIST(const SOCKET s, unsigned int *RequestID, unsigned int *Unk_0, unsigned char *SearchString)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_GAMELIST: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[512];
	ZeroMemory(packet_buffer, 512);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_GAMELIST;

	//RequestID
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *(unsigned short*)(RequestID);
	*(unsigned short*)(packet_buffer + 0) += 2;
	//Unk_0
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *Unk_0;
	*(unsigned short*)(packet_buffer + 0) += 4;
	//SearchString
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), SearchString, strlen((const char*)SearchString));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;


	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_GAMELIST: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_GAMEINFO(const SOCKET s, unsigned int *RequestID, unsigned char *GameName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_GAMEINFO: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[512];
	ZeroMemory(packet_buffer, 512);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_GAMEINFO;

	//RequestID
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *(unsigned short*)(RequestID);
	*(unsigned short*)(packet_buffer + 0) += 2;
	//GameName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), GameName, strlen((const char*)GameName));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_GAMEINFO: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_CHARLOGON(const SOCKET s, unsigned char *CharName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_CHARLOGON: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[128];
	ZeroMemory(packet_buffer, 128);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_CHARLOGON;

	//CharName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), CharName, strlen((const char*)CharName));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;


	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_CHARLOGON: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_CHARDELETE(const SOCKET s, unsigned int *Unk_0, unsigned char *CharName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_CHARDELETE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[512];
	ZeroMemory(packet_buffer, 512);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_CHARDELETE;

	//RequestID
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *(unsigned short*)(Unk_0);
	*(unsigned short*)(packet_buffer + 0) += 2;
	//CharName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), CharName, strlen((const char*)CharName));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_CHARDELETE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_REQUESTLADDERDATA(const SOCKET s, unsigned int *LadderType, unsigned int *Position)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_REQUESTLADDERDATA: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[6];
	ZeroMemory(packet_buffer, 6);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_CHARDELETE;

	//LadderType
	*(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *(unsigned char*)(LadderType);
	*(unsigned short*)(packet_buffer + 0) += 1;
	//Position
	*(unsigned short*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *(unsigned short*)(Position);
	*(unsigned short*)(packet_buffer + 0) += 2;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_REQUESTLADDERDATA: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_MOTD(const SOCKET s)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_MOTD: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[3];
	ZeroMemory(packet_buffer, 3);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_MOTD;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_MOTD: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_CANCELGAMECREATE(const SOCKET s)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_CANCELGAMECREATE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[3];
	ZeroMemory(packet_buffer, 3);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_CANCELGAMECREATE;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_CANCELGAMECREATE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_CHARRANK(const SOCKET s, unsigned int *Hardcore, unsigned int *Expansion, unsigned char *CharName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_CHARRANK: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[64];
	ZeroMemory(packet_buffer, 64);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_CHARRANK;

	//Hardcore
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *Hardcore;
	*(unsigned short*)(packet_buffer + 0) += 4;
	//Expansion
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *Expansion;
	*(unsigned short*)(packet_buffer + 0) += 4;
	//CharName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), CharName, strlen((const char*)CharName));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_CHARRANK: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_CHARUPGRADE(const SOCKET s, unsigned char *CharName)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_CHARUPGRADE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[64];
	ZeroMemory(packet_buffer, 64);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_CHARUPGRADE;

	//CharName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))), CharName, strlen((const char*)CharName));
	*(unsigned short*)(packet_buffer + 0) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_CHARUPGRADE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 MCP_CHARLIST2(const SOCKET s, unsigned int *RequestedCount)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("MCP_CHARLIST2: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[7];
	ZeroMemory(packet_buffer, 7);

	*(unsigned short*)(packet_buffer + 0) = (unsigned short)0x0003; //(head length + id)
	*(packet_buffer + 2) = ID_MCP_CHARLIST2;

	//CharClass
	*(unsigned int*)(packet_buffer + (*(unsigned short*)(packet_buffer + 0))) = *RequestedCount;
	*(unsigned short*)(packet_buffer + 0) += 4;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + 0), 0);

#ifdef _DEBUG
	OutputDebugString("MCP_CHARLIST2: HAS BEEN SENT\r\n");
#endif
}

#pragma endregion

#pragma region "BOTNET PACKET LISTING"

void VB6_API2 BOTNET_KEEPALIVE(const SOCKET s)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_KEEPALIVE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_KEEPALIVE;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_KEEPALIVE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 BOTNET_LOGON(const SOCKET s, unsigned char *BotName, unsigned char *BotPassword)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_LOGON: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN + BOTNET_NAME_MAX + BOTNET_PASSWORD_MAX];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN + BOTNET_NAME_MAX + BOTNET_PASSWORD_MAX);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_LOGON;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	//Test lengths
	if (!(strlen((const char *)BotName) < BOTNET_NAME_MAX) || (strlen((const char *)BotName) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_LOGON Error: Bot name BadLength or was Empty\r\n");
#endif
		return;
	}
	if (!(strlen((const char *)BotPassword) < BOTNET_PASSWORD_MAX) || (strlen((const char *)BotPassword) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_LOGON Error: Bot password BadLength or was Empty\r\n");
#endif
		return;
	}
	//BotName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), BotName, strlen((const char*)BotName));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
	//BotPassword
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), BotPassword, strlen((const char*)BotPassword));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_LOGON: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 BOTNET_STATSUPDATE(const SOCKET s, unsigned char *BNName, unsigned char *BNChannel, unsigned int *BNIP, unsigned char *DB_N_PW, unsigned int *CycleState)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_STATSUPDATE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN + BOTNET_BNET_NAME_MAX + BOTNET_BNET_CHANNELNAME_MAX + DW_LEN + BOTNET_DB_PASS_MAX + DW_LEN];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN + BOTNET_BNET_NAME_MAX + BOTNET_BNET_CHANNELNAME_MAX + DW_LEN + BOTNET_DB_PASS_MAX + DW_LEN);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_STATSUPDATE;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	//Test lengths
	if (!(strlen((const char *)BNName) < BOTNET_BNET_NAME_MAX) || (strlen((const char *)BNName) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_STATSUPDATE Error: Bnet name BadLength or was Empty\r\n");
#endif
		return;
	}
	if (!(strlen((const char *)BNChannel) < BOTNET_BNET_CHANNELNAME_MAX) || (strlen((const char *)BNChannel) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_STATSUPDATE Error: Bnet channel BadLength or was Empty\r\n");
#endif
		return;
	}
	if (!(strlen((const char *)DB_N_PW) < BOTNET_DB_PASS_MAX) || (strlen((const char *)DB_N_PW) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_STATSUPDATE Error: DB + PW BadLength or was Empty\r\n");
#endif
		return;
	}

	//BNName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), BNName, strlen((const char*)BNName));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
	//BNChannel
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), BNChannel, strlen((const char*)BNChannel));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
	//BNIP
	*(unsigned int*)(packet_buffer + BOTNET_LEN_POS) = *BNIP;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += DW_LEN;
	//DB_N_PW
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), DB_N_PW, strlen((const char*)DB_N_PW));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
	//CycleState
	*(unsigned int*)(packet_buffer + BOTNET_LEN_POS) = *CycleState;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_STATSUPDATE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 BOTNET_DATABASE(const SOCKET s, unsigned int *SubCommand, unsigned int *MaxAge, unsigned char *UserMask, unsigned char *Flags, unsigned char *Comment)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_DATABASE: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN + BOTNET_USERMASK_MAX + BOTNET_FLAGSTR_MAX + BOTNET_COMMENT_MAX];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN + BOTNET_USERMASK_MAX + BOTNET_FLAGSTR_MAX + BOTNET_COMMENT_MAX);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_DATABASE;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	switch (*SubCommand)
	{
	case 0x01: //Request database
		*(unsigned int*)(packet_buffer + BOTNET_LEN_POS) = *MaxAge;
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += DW_LEN;
		break;
	case 0x02: //Modify entry
		if (!(strlen((const char *)UserMask) < BOTNET_USERMASK_MAX) || (strlen((const char *)UserMask) == 0))
		{
#ifdef _DEBUG
			OutputDebugString("BOTNET_DATABASE Error: UserMask BadLength or was Empty\r\n");
#endif
			return;
		}
		if (!(strlen((const char *)Flags) < BOTNET_USERMASK_MAX))
		{
#ifdef _DEBUG
			OutputDebugString("BOTNET_DATABASE Error: Flags BadLength\r\n");
#endif
			return;
		}
		if (!(strlen((const char *)Comment) < BOTNET_COMMENT_MAX))
		{
#ifdef _DEBUG
			OutputDebugString("BOTNET_DATABASE Error: Flags BadLength\r\n");
#endif
			return;
		}
		//UserMask
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), UserMask, strlen((const char*)UserMask));
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
		//Flags
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), Flags, strlen((const char*)Flags));
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
		//Comment
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), Comment, strlen((const char*)Comment));
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
		break;
	case 0x03: //Remove entry
		if (!(strlen((const char *)UserMask) < BOTNET_USERMASK_MAX) || (strlen((const char *)UserMask) == 0))
		{
#ifdef _DEBUG
			OutputDebugString("BOTNET_DATABASE Error: UserMask BadLength or was Empty\r\n");
#endif
			return;
		}
		if (!(strlen((const char *)Comment) < BOTNET_COMMENT_MAX))
		{
#ifdef _DEBUG
			OutputDebugString("BOTNET_DATABASE Error: Flags BadLength\r\n");
#endif
			return;
		}
		//UserMask
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), UserMask, strlen((const char*)UserMask));
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
		//Comment
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), Comment, strlen((const char*)Comment));
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
		break;
	default:
#ifdef _DEBUG
		OutputDebugString("BOTNET_DATABASE Error: Unknowen SubCommand\r\n");
#endif
		return;
	}

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_DATABASE: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 BOTNET_COMMAND_DB(const SOCKET s, unsigned char *SenderName, unsigned char *Command)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_COMMAND_DB: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN + BOTNET_NAME_MAX + BOTNET_COMMAND_MAX];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN + BOTNET_NAME_MAX + BOTNET_COMMAND_MAX);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_COMMAND_DB;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	//Test lengths
	if (!(strlen((const char *)SenderName) < BOTNET_NAME_MAX) || (strlen((const char *)SenderName) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_COMMAND_DB Error: Bot name BadLength or was Empty\r\n");
#endif
		return;
	}
	if (!(strlen((const char *)Command) < BOTNET_COMMAND_MAX) || (strlen((const char *)Command) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_COMMAND_DB Error: Bot password BadLength or was Empty\r\n");
#endif
		return;
	}

	//SenderName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), SenderName, strlen((const char*)SenderName));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
	//Command
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), Command, strlen((const char*)Command));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_COMMAND_DB: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 BOTNET_USER_LIST(const SOCKET s)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_USER_LIST: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_USER_LIST;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_USER_LIST: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 BOTNET_COMMAND_ALL(const SOCKET s, unsigned char *SenderName, unsigned char *Command)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_COMMAND_ALL: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN + BOTNET_NAME_MAX + BOTNET_COMMAND_MAX];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN + BOTNET_NAME_MAX + BOTNET_COMMAND_MAX);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_COMMAND_ALL;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	//Test lengths
	if (!(strlen((const char *)SenderName) < BOTNET_NAME_MAX) || (strlen((const char *)SenderName) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_COMMAND_ALL Error: Bot name BadLength or was Empty\r\n");
#endif
		return;
	}
	if (!(strlen((const char *)Command) < BOTNET_COMMAND_MAX) || (strlen((const char *)Command) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_COMMAND_ALL Error: Bot password BadLength or was Empty\r\n");
#endif
		return;
	}

	//SenderName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), SenderName, strlen((const char*)SenderName));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
	//Command
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), Command, strlen((const char*)Command));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_COMMAND_ALL: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 BOTNET_COMMAND_TO(const SOCKET s, unsigned int *TargetID, unsigned char *SenderName, unsigned char *Command)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_COMMAND_TO: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN + DW_LEN + BOTNET_NAME_MAX + BOTNET_COMMAND_MAX];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN + DW_LEN + BOTNET_NAME_MAX + BOTNET_COMMAND_MAX);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_COMMAND_TO;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	//Test lengths
	if (!(strlen((const char *)SenderName) < BOTNET_NAME_MAX) || (strlen((const char *)SenderName) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_COMMAND_TO Error: Bot name BadLength or was Empty\r\n");
#endif
		return;
	}
	if (!(strlen((const char *)Command) < BOTNET_COMMAND_MAX) || (strlen((const char *)Command) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_COMMAND_TO Error: Bot password BadLength or was Empty\r\n");
#endif
		return;
	}

	//TargetID
	*(unsigned int*)(packet_buffer + BOTNET_LEN_POS) = *TargetID;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += DW_LEN;
	//SenderName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), SenderName, strlen((const char*)SenderName));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
	//Command
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), Command, strlen((const char*)Command));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_COMMAND_TO: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 BOTNET_DATABASE_CHPW(const SOCKET s, unsigned int *PasswordSelect, unsigned char *NewPassword)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_DATABASE_CHPW: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN + DW_LEN + BOTNET_PASSWORD_MAX];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN + DW_LEN + BOTNET_PASSWORD_MAX);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_DATABASE_CHPW;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	//Test lengths
	if (!(strlen((const char *)NewPassword) < BOTNET_PASSWORD_MAX) || (strlen((const char *)NewPassword) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_DATABASE_CHPW Error: Bot password BadLength or was Empty\r\n");
#endif
		return;
	}

	//TargetID
	*(unsigned int*)(packet_buffer + BOTNET_LEN_POS) = *PasswordSelect;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += DW_LEN;
	//NewPassword
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), NewPassword, strlen((const char*)NewPassword));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_DATABASE_CHPW: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 BOTNET_CLIENT_VERSION(const SOCKET s, unsigned int *ClientAwareness, unsigned int *ClientCapabilities)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_CLIENT_VERSION: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN + DW_LEN + DW_LEN];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN + DW_LEN + DW_LEN);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_CLIENT_VERSION;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	//ClientAwareness
	*(unsigned int*)(packet_buffer + BOTNET_LEN_POS) = *ClientAwareness;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += DW_LEN;
	//ClientCapabilities
	*(unsigned int*)(packet_buffer + BOTNET_LEN_POS) = *ClientCapabilities;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += DW_LEN;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_CLIENT_VERSION: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 BOTNET_CHAT(const SOCKET s, unsigned int *Distribution, unsigned int *Action, unsigned int *TargetID, unsigned char *Message)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_CHAT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN + DW_LEN + DW_LEN + DW_LEN + BOTNET_MESSAGE_MAX];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN + DW_LEN + DW_LEN + DW_LEN + BOTNET_MESSAGE_MAX);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_CHAT;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	//Test lengths
	if (!(strlen((const char *)Message) < BOTNET_MESSAGE_MAX) || (strlen((const char *)Message) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_CHAT Error: Message BadLength or was Empty\r\n");
#endif
		return;
	}

	//Distribution
	*(unsigned int*)(packet_buffer + BOTNET_LEN_POS) = *Distribution;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += DW_LEN;
	//Action
	*(unsigned int*)(packet_buffer + BOTNET_LEN_POS) = *Action;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += DW_LEN;
	//TargetID
	*(unsigned int*)(packet_buffer + BOTNET_LEN_POS) = *TargetID;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += DW_LEN;
	//Message
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), Message, strlen((const char*)Message));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_CHAT: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 BOTNET_ACCOUNT(const SOCKET s, unsigned int *SubCommand, unsigned char *AccountName, unsigned char *Password, unsigned char *OldPassword)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_ACCOUNT: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN + DW_LEN + BOTNET_ACCOUNT_MAX + BOTNET_DB_PASS_MAX + BOTNET_DB_PASS_MAX];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN + DW_LEN + BOTNET_ACCOUNT_MAX + BOTNET_DB_PASS_MAX + BOTNET_DB_PASS_MAX);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_ACCOUNT;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	//Test lengths
	if (!(strlen((const char *)AccountName) < BOTNET_ACCOUNT_MAX) || (strlen((const char *)AccountName) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_ACCOUNT Error: AccountName BadLength or was Empty\r\n");
#endif
		return;
	}
	if (!(strlen((const char *)Password) < BOTNET_DB_PASS_MAX) || (strlen((const char *)Password) == 0))
	{
#ifdef _DEBUG
		OutputDebugString("BOTNET_ACCOUNT Error: Password BadLength or was Empty\r\n");
#endif
		return;
	}

	//SubCommand
	*(unsigned int*)(packet_buffer + BOTNET_LEN_POS) = *SubCommand;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += DW_LEN;
	//AccountName
	memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), AccountName, strlen((const char*)AccountName));
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;

	switch (*SubCommand)
	{
	case 0x00: //Log on
		//Password
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), Password, strlen((const char*)Password));
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
		break;
	case 0x01: //Change Password
		if (!(strlen((const char *)OldPassword) < BOTNET_DB_PASS_MAX))
		{
#ifdef _DEBUG
			OutputDebugString("BOTNET_ACCOUNT Error: Old password BadLength\r\n");
#endif
			return;
		}
		//OldPassword
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), OldPassword, strlen((const char*)OldPassword));
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
		//Password
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), Password, strlen((const char*)Password));
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
		break;
	case 0x02: //Create
		//Password
		memcpy((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + BOTNET_LEN_POS))), Password, strlen((const char*)Password));
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += strlen((char *)(packet_buffer + (*(unsigned short*)(packet_buffer + 0)))) + 1;
		break;
	default:
#ifdef _DEBUG
		OutputDebugString("BOTNET_ACCOUNT Error: Unknowen SubCommand\r\n");
#endif
		return;
	}

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_ACCOUNT: HAS BEEN SENT\r\n");
#endif
}

void VB6_API2 BOTNET_CHAT_OPTIONS(const SOCKET s, unsigned int *bRequest, unsigned char *SubCommand, unsigned char *Broadcast, unsigned char *Database, unsigned char *Whisper, unsigned char *Other)
{
	if (s == INVALID_SOCKET)
	{
		//type up a debug print out of the error
#ifdef _DEBUG
		OutputDebugString("BOTNET_CHAT_OPTIONS: INVALID_SOCKET\r\n");
#endif
		return;
	} //vb6 socket handle was -1 (not initalized / not bound)

	unsigned char packet_buffer[BOTNET_BASEHEAD_LEN + 5];
	ZeroMemory(packet_buffer, BOTNET_BASEHEAD_LEN + 5);

	*(packet_buffer + 0) = BOTNET_PROTO;
	*(packet_buffer + 1) = ID_BOTNET_CHAT_OPTIONS;
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) = (unsigned short)BOTNET_BASEHEAD_LEN;

	*(packet_buffer + BOTNET_LEN_POS) = SubCommand[0];
	*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += 1;

	if (bRequest != 0)
	{
		*(packet_buffer + BOTNET_LEN_POS) = Broadcast[0];
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += 1;
		*(packet_buffer + BOTNET_LEN_POS) = Database[0];
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += 1;
		*(packet_buffer + BOTNET_LEN_POS) = Whisper[0];
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += 1;
		*(packet_buffer + BOTNET_LEN_POS) = Other[0];
		*(unsigned short*)(packet_buffer + BOTNET_LEN_POS) += 1;
	}

	send(s, (const char *)packet_buffer, *(unsigned short*)(packet_buffer + BOTNET_LEN_POS), 0);

#ifdef _DEBUG
	OutputDebugString("BOTNET_CHAT_OPTIONS: HAS BEEN SENT\r\n");
#endif
}

#pragma endregion
