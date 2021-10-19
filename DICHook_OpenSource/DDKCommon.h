#pragma once
#ifndef __DDKCOMMON_INCLUDED_

#pragma comment(lib,"oldnames.lib")
#pragma comment(linker,"/INCREMENTAL:NO")

#include "ntifs.h"
#include "ntimage.h"
#include "MyPEB.h"
#include "NtFunctionDefine.h"
#include "KernelAsm.h"
#include "MyMemoryIo64.h"

//#define print DbgPrint
#define print

#define WIN10 (10240)
#define WIN10_1507 (10240)
#define WIN10_1511 (10586)
#define WIN10_1607 (14393)
#define WIN10_1703 (15063)
#define WIN10_1709 (16299)
#define WIN10_1803 (17134)
#define WIN10_1809 (17763)
#define WIN10_1903 (18362)
#define WIN10_1909 (18363)
#define WIN10_2004 (19041)
#define WIN10_21H1 (19043)

#define POOL_TAG 'enoN'

typedef struct _XINPUT_GAMEPAD
{
	WORD                                wButtons;
	BYTE                                bLeftTrigger;
	BYTE                                bRightTrigger;
	SHORT                               sThumbLX;
	SHORT                               sThumbLY;
	SHORT                               sThumbRX;
	SHORT                               sThumbRY;
} XINPUT_GAMEPAD, * PXINPUT_GAMEPAD;

typedef struct _XINPUT_STATE
{
	DWORD                               dwPacketNumber;
	XINPUT_GAMEPAD                      Gamepad;
} XINPUT_STATE, * PXINPUT_STATE;

typedef struct _KBuffer {
	PVOID Address;
	ULONG Size;
}KBuffer, * PKBuffer;

#ifdef __cplusplus
extern "C"{
#endif

LPWSTR WINAPI StrStrIW(LPCWSTR lpszStr, LPCWSTR lpszSearch);
LPSTR WINAPI StrStrIA(LPCSTR lpszStr, LPCSTR lpszSearch);

VOID Sleep(LONG Millsecond);
ULONG64 GetRealTime();
ULONG64 GetRealMicroTime();
LPSTR WINAPI StrStrIA(LPCSTR lpszStr, LPCSTR lpszSearch);
LPWSTR WINAPI StrStrIW(LPCWSTR lpszStr, LPCWSTR lpszSearch);
LPWSTR WINAPI StrStrNIW(LPCWSTR lpszStr, LPCWSTR lpszSearch, SIZE_T max_chars);
LPSTR WINAPI StrStrNIA(LPCSTR lpszStr, LPCSTR lpszSearch, SIZE_T max_chars);

INT64 FindSignatureCode_nocheck(LPCVOID Memory, UINT64 MemoryLenth, LPCSTR SignatureCode, UINT64 Pos);

ULONG64 ScanSection(LPCSTR SectionName, LPCSTR Pattern);
ULONG64 ScanSection_Image(LPCVOID hImage, LPCSTR SectionName, LPCSTR Pattern);
ULONG64 KGetProcessCr3(PEPROCESS Process);

PVOID KGetDriverImageBase(LPCWSTR DriverName);
PVOID KGetDriverImageBase2(PCHAR name);
ULONG KGetDriverImageSize(LPCWSTR DriverName);

PVOID KGetProcAddress(PVOID ModuleHandle, LPCSTR ProcName);
ULONG KGetBuildNumber();
PVOID KGetNtoskrnl();

PVOID64 KGetPteBase();

typedef struct _IRQL_STATE {
	ULONG old_irql;
}IRQL_STATE, * PIRQL_STATE;

VOID KRaiseIrqlToDpcOrHigh(PIRQL_STATE state);
VOID KLowerIrqlToState(PIRQL_STATE state);

ULONG64 KGetRspBase();

#ifdef __cplusplus
}
#endif

#endif // !__DDKCOMMON_INCLUDED_



