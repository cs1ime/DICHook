//author :cslime
//https://github.com/CS1ime/DICHook

#include "DDKCommon.h"
#include "MyMemoryIo64.h"

#pragma comment(lib,"oldnames.lib")

typedef struct _SBYTEINFO_3 {
	UCHAR RawByte;
	UCHAR Hi : 1; //Hi 4 bit is ??
	UCHAR Lo : 1; //Lo 4 bit is ??
	UCHAR All : 1;
	UCHAR No : 1;
}SBYTEINFO_3, *PSBYTEINFO_3;
typedef struct _SBYTEINFO_2 {
	UCHAR RawByte;
	BOOLEAN All;
}SBYTEINFO_2, *PSBYTEINFO_2;

void AnsiToUnicode(LPCSTR AnsiStr, LPWSTR UnicodeStrBuffer, ULONG MaxLenth) {
	int len = strlen(AnsiStr);
	if (len > MaxLenth)len = MaxLenth;
	UnicodeStrBuffer[len] = 0;
	for (int i = 0; i < len; ++i) {
		UnicodeStrBuffer[i] = AnsiStr[i];
	}
	return;
}
void UnicodeToAnsi(LPCWSTR UnicodeStr, LPSTR AnsiStrBuffer, ULONG MaxLenth) {
	int len = wcslen(UnicodeStr);
	if (len > MaxLenth)len = MaxLenth;

	AnsiStrBuffer[len] = 0;
	for (int i = 0; i < len; ++i) {
		AnsiStrBuffer[i] = UnicodeStr[i];
	}
	return;
}

LPWSTR WINAPI StrStrIW(LPCWSTR lpszStr, LPCWSTR lpszSearch)
{
	int iLen;
	LPCWSTR end;

	if (!lpszStr || !lpszSearch || !*lpszSearch)
		return NULL;

	iLen = wcslen(lpszSearch);
	end = lpszStr + wcslen(lpszStr);

	while (lpszStr + iLen <= end)
	{
		if (!wcsnicmp(lpszStr, lpszSearch, iLen))
			return (LPWSTR)lpszStr;
		lpszStr++;
	}
	return NULL;
}
LPWSTR WINAPI StrStrNIW(LPCWSTR lpszStr, LPCWSTR lpszSearch, SIZE_T max_chars)
{
	int iLen;
	LPCWSTR end;

	if (!lpszStr || !lpszSearch || !*lpszSearch || !max_chars)
		return NULL;

	iLen = wcslen(lpszSearch);
	end = lpszStr + max_chars;

	while (lpszStr + iLen <= end)
	{
		if (!wcsnicmp(lpszStr, lpszSearch, iLen))
			return (LPWSTR)lpszStr;
		lpszStr++;
	}
	return NULL;
}
LPSTR WINAPI StrStrIA(LPCSTR lpszStr, LPCSTR lpszSearch)
{
	int iLen;
	LPCSTR end;

	if (!lpszStr || !lpszSearch || !*lpszSearch)
		return NULL;

	iLen = strlen(lpszSearch);
	end = lpszStr + strlen(lpszStr);

	while (lpszStr + iLen <= end)
	{
		if (!strnicmp(lpszStr, lpszSearch, iLen))
			return (LPSTR)lpszStr;
		lpszStr++;
	}
	return NULL;
}
LPSTR WINAPI StrStrNIA(LPCSTR lpszStr, LPCSTR lpszSearch, SIZE_T max_chars)
{
	int iLen;
	LPCSTR end;

	if (!lpszStr || !lpszSearch || !*lpszSearch || !max_chars)
		return NULL;

	iLen = strlen(lpszSearch);
	end = lpszStr + max_chars;

	while (lpszStr + iLen <= end)
	{
		if (!strnicmp(lpszStr, lpszSearch, iLen))
			return (LPSTR)lpszStr;
		lpszStr++;
	}
	return NULL;
}

UCHAR CharToByte(UCHAR c) {
	if (c >= '0' && c <= '9') return(c - 48);
	else if (c >= 'A' && c <= 'F')return(c - 55);
	else if (c >= 'a' && c <= 'f')return(c - 87);
	return 0;
}
#define STRTOBYTE(h) (CharToByte(h[0]) * 0x10 + CharToByte(h[1]))
UCHAR StrToByte(const char* hex) {
	return CharToByte(hex[0]) * 0x10 + CharToByte(hex[1]);
}
ULONG __strlen__(LPCSTR str) {
	register ULONG len = 0;
	while (*str++)++len;
	return len;
}
#define CHECKCHARVALID(v) ((v >= '0' && v <= '9') || (v >= 'A' && v <= 'F') || (v >= 'a' && v <= 'f') || v == '?')
ULONG CheckForSignureCode(LPCSTR scode) {
	ULONG len = __strlen__(scode);
	LPCSTR str = scode;
	if (len % 2)return FALSE;
	str = scode;
	ULONG Type = 1;
	for (int i = 0; i < len; i += 2) {
		if (!CHECKCHARVALID(scode[i]) || !CHECKCHARVALID(scode[i + 1]))return 0;
		if (scode[i] == '?' && scode[i + 1] != '?') {
			return 3;
		}
		if (scode[i + 1] == '?' && scode[i] != '?') {
			return 3;
		}
		if (scode[i] == '?' && scode[i + 1] == '?')Type = 2;
	}
	return Type;
}

#define HI4BIT(v) (v>>4)
#define LO4BIT(v) (v&0x0f)

BOOLEAN __forceinline CompareByte_3(UCHAR byte, PSBYTEINFO_3 sbyte) {
	if (sbyte->No)return byte == sbyte->RawByte;
	if (sbyte->All) return TRUE;
	if (sbyte->Hi) {
		return sbyte->RawByte == LO4BIT(byte);
	}
	if (sbyte->Lo) {
		return sbyte->RawByte == HI4BIT(byte);
	}
	return FALSE;
}
VOID __forceinline convert_scode_sbyte_3(LPCSTR SignatureCode, PSBYTEINFO_3 rawbyte) {
	ULONG len = __strlen__(SignatureCode) / 2;
	memset(rawbyte, 0, len * sizeof(SBYTEINFO_3));
	for (int i = 0; i < len; i++) {
		LPCSTR scode = SignatureCode + i * 2;
		if (scode[0] == '?' && scode[1] == '?') {
			rawbyte[i].All = TRUE;
			continue;
		}
		if (scode[0] == '?') {
			rawbyte[i].Hi = TRUE;
			rawbyte[i].RawByte = CharToByte(scode[1]);
			continue;
		}
		if (scode[1] == '?') {
			rawbyte[i].Lo = TRUE;
			rawbyte[i].RawByte = CharToByte(scode[0]);
			continue;
		}
		rawbyte[i].RawByte = STRTOBYTE(scode);
		rawbyte[i].No = TRUE;
	}
}
VOID __forceinline convert_scode_sbyte_2(LPCSTR SignatureCode, PSBYTEINFO_2 rawbyte) {
	ULONG len = __strlen__(SignatureCode) / 2;
	memset(rawbyte, 0, len * sizeof(SBYTEINFO_2));
	for (int i = 0; i < len; i++) {
		LPCSTR scode = SignatureCode + i * 2;
		if (scode[0] == '?') {
			rawbyte[i].All = TRUE;
			continue;
		}
		rawbyte[i].RawByte = STRTOBYTE(scode);
	}
}
INT64 FindSignatureCode_3_nocheck(const PUCHAR Memory, UINT64 MemoryLenth, LPCSTR SignatureCode, UINT64 Pos) {
	ULONG len = __strlen__(SignatureCode) / 2;
	if (len > 100)
		return -1;
	SBYTEINFO_3 rawbyte[100];
	memset(rawbyte, 0, sizeof(rawbyte));

	convert_scode_sbyte_3(SignatureCode, rawbyte);

	register PSBYTEINFO_3 sbyte = rawbyte;
	UINT64 opos = 0;
	register UINT64 cmppos = 0;
	register BOOLEAN Hit = FALSE;
	for (UINT64 i = Pos; i < MemoryLenth; ++i) {
			if (CompareByte_3(Memory[i], sbyte)) {
				if (!Hit) {
					opos = i;
					Hit = TRUE;
				}
				++sbyte;
				if (++cmppos == len) {
					return i - (len - 1);
				}
			}
			else {
				if (Hit) {
					if (Hit)i = opos;
					Hit = FALSE;
					cmppos = 0;
					sbyte = rawbyte;
				}
			}

	}
	return -1;
}
INT64 FindSignatureCode_2_nocheck(const PUCHAR Memory, UINT64 MemoryLenth, LPCSTR SignatureCode, UINT64 Pos) {
	ULONG len = __strlen__(SignatureCode) / 2;
	ULONG PoolSize = len * sizeof(SBYTEINFO_2);

	if (len > 100)
		return -1;
	SBYTEINFO_2 rawbyte[100];
	memset(rawbyte, 0, sizeof(rawbyte));

	convert_scode_sbyte_2(SignatureCode, rawbyte);

	register PSBYTEINFO_2 sbyte = rawbyte;
	UINT64 opos = 0;
	register UINT64 cmppos = 0;
	register BOOLEAN Hit = FALSE;
	for (register UINT64 i = Pos; i < MemoryLenth; ++i) {
			if (sbyte->All || (Memory[i] == sbyte->RawByte)) {
				if (!Hit) {
					opos = i;
					Hit = TRUE;
				}
				++sbyte;
				if (++cmppos == len) {
					return i - (len - 1);
				}
			}
			else {
				if (Hit) {
					i = opos;
					Hit = FALSE;
					cmppos = 0;
					sbyte = rawbyte;
				}
			}
	}
	return -1;
}
INT64 FindSignatureCode_nocheck(LPCVOID Memory, UINT64 MemoryLenth, LPCSTR SignatureCode, UINT64 Pos) {
	CHAR realPattern[300];
	RtlZeroMemory(realPattern, sizeof(realPattern));
	int len = strlen(SignatureCode);
	int j = 0;
	for (int i = 0; i < len; i++) {
		if (SignatureCode[i] != ' ') {
			realPattern[j++] = SignatureCode[i];
			if (j > 299)
				break;
		}
	}

	ULONG type = CheckForSignureCode(realPattern);
	if (!type)return -1;
	if (type == 3)return FindSignatureCode_3_nocheck((const PUCHAR)Memory, MemoryLenth, realPattern, Pos);
	if (type == 2 || type == 1) return FindSignatureCode_2_nocheck((const PUCHAR)Memory, MemoryLenth, realPattern, Pos);

	return -1;
}

ULONG64 ScanSection(LPCSTR SectionName, LPCSTR Pattern) {
	PIMAGE_NT_HEADERS pHdr;
	PIMAGE_SECTION_HEADER pFirstSec;
	PIMAGE_SECTION_HEADER pSec;
	PUCHAR ntosBase;

	ntosBase = (PUCHAR)KGetNtoskrnl();

	if (!ntosBase)
		return NULL;
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)ntosBase;
	pHdr = (IMAGE_NT_HEADERS*)(ntosBase + idh->e_lfanew);
	pFirstSec = IMAGE_FIRST_SECTION(pHdr);
	for (pSec = pFirstSec; pSec < pFirstSec + pHdr->FileHeader.NumberOfSections; pSec++)
	{
		CHAR Name[9];
		RtlZeroMemory(&Name, 9);
		memcpy(Name, pSec->Name, 8);
		if (!strcmp(SectionName, Name))
		{
			PUCHAR pFound = NULL;
			INT64 pos = FindSignatureCode_nocheck(ntosBase + pSec->VirtualAddress, pSec->Misc.VirtualSize, Pattern, 0);
			if (pos != -1)
			{
				return (ULONG64)(pos + ntosBase + pSec->VirtualAddress);
			}

		}
	}
	return NULL;
}
ULONG64 ScanSection_Image(LPCVOID hImage, LPCSTR SectionName, LPCSTR Pattern) {
	PIMAGE_NT_HEADERS pHdr;
	PIMAGE_SECTION_HEADER pFirstSec;
	PIMAGE_SECTION_HEADER pSec;
	PUCHAR ntosBase;

	ntosBase = (PUCHAR)hImage;

	if (!ntosBase)
		return NULL;
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)ntosBase;
	pHdr = (IMAGE_NT_HEADERS*)(ntosBase + idh->e_lfanew);
	pFirstSec = IMAGE_FIRST_SECTION(pHdr);
	for (pSec = pFirstSec; pSec < pFirstSec + pHdr->FileHeader.NumberOfSections; pSec++)
	{
		CHAR Name[9];
		RtlZeroMemory(&Name, 9);
		memcpy(Name, pSec->Name, 8);
		if (!strcmp(SectionName, Name))
		{
			PUCHAR pFound = NULL;
			INT64 pos = FindSignatureCode_nocheck(ntosBase + pSec->VirtualAddress, pSec->Misc.VirtualSize, Pattern, 0);
			if (pos != -1)
			{
				return (ULONG64)(pos + ntosBase + pSec->VirtualAddress);
			}

		}
	}
	return NULL;
}
PVOID KGetDriverImageBase2(PCHAR name) {
	PVOID addr = 0;

	ULONG size = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		return addr;
	}

	PSYSTEM_MODULE_INFORMATION modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, size, POOL_TAG);
	if (!modules) {
		return addr;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
		return addr;
	}
	int name_len = strlen(name);
	for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
		SYSTEM_MODULE m = modules->Modules[i];
		UCHAR buf[256 + 1];
		RtlZeroMemory(buf, sizeof(buf));
		memcpy(buf, m.FullPathName, 256);
		if (StrStrIA((LPCSTR)buf, name)) {
			addr = m.ImageBase;
			break;
		}
	}

	ExFreePoolWithTag(modules, POOL_TAG);
	return addr;
}
ULONG KGetDriverImageSize2(PCHAR name) {
	ULONG addr = 0;

	ULONG size = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		return addr;
	}

	PSYSTEM_MODULE_INFORMATION modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, size, POOL_TAG);
	if (!modules) {
		return addr;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
		return addr;
	}

	for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
		SYSTEM_MODULE m = modules->Modules[i];
		UCHAR buf[256 + 1];
		RtlZeroMemory(buf, sizeof(buf));
		memcpy(buf, m.FullPathName, 256);
		if (StrStrIA((LPCSTR)buf, name)) {
			addr = m.ImageSize;
			break;
		}
	}

	ExFreePoolWithTag(modules, POOL_TAG);
	return addr;
}
PVOID KGetDriverImageBase(LPCWSTR DriverName) {
	CHAR str[300];
	UnicodeToAnsi(DriverName, str, 300);
	return KGetDriverImageBase2(str);
}
ULONG KGetDriverImageSize(LPCWSTR DriverName) {
	CHAR str[300];
	UnicodeToAnsi(DriverName, str, 300);
	return KGetDriverImageSize2(str);
}
ULONG64 KGetProcessCr3(PEPROCESS Process) {
	return *(PULONG64)(((PUCHAR)Process) + 0x28);
}
ULONG g_cachedBuildNumber = 0;
ULONG KGetBuildNumber() {
	if (g_cachedBuildNumber)
		return g_cachedBuildNumber;
	RTL_OSVERSIONINFOW ow;
	if (!NT_SUCCESS(RtlGetVersion(&ow))) {
		return 0;
	}
	g_cachedBuildNumber = ow.dwBuildNumber;
	return ow.dwBuildNumber;
}

PVOID g_NtoskrnlBase = 0;
PVOID g_HaldllBase = 0;

PVOID KGetNtoskrnl() {
	if (g_NtoskrnlBase) {
		return g_NtoskrnlBase;
	}
	g_NtoskrnlBase = KGetDriverImageBase2("ntoskrnl.exe");
	return g_NtoskrnlBase;
}
PVOID KGetProcAddress(PVOID ModuleHandle, LPCSTR ProcName) {
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)ModuleHandle;
	IMAGE_NT_HEADERS64 *inh = (IMAGE_NT_HEADERS64 *)(idh->e_lfanew + (PUCHAR)idh);
	IMAGE_EXPORT_DIRECTORY *ied = (IMAGE_EXPORT_DIRECTORY *)((PUCHAR)ModuleHandle + inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	for (int i = 0; i < ied->NumberOfNames; i++) {
		WORD index = ((WORD *)((PUCHAR)ModuleHandle + ied->AddressOfNameOrdinals))[i];
		ULONG NameRVA = ((ULONG *)((PUCHAR)ModuleHandle + ied->AddressOfNames))[i];
		PCSTR Name = (PCSTR)(((ULONG64)ModuleHandle) + NameRVA);

		if (!strcmp(Name, ProcName)) {
			ULONG FunRVA = ((ULONG *)((PUCHAR)ModuleHandle + ied->AddressOfFunctions))[index];
			PUCHAR FunAddress = ((PUCHAR)ModuleHandle + FunRVA);

			BOOLEAN IsBoundImport = FALSE;
			ULONG BoundImportNameLenth = 0;
			for (ULONG i = 0; i < 50; i++) {
				PUCHAR pAddr = FunAddress + i;
				UCHAR c = *pAddr;
				if (c == '.' && i > 0) {
					IsBoundImport = TRUE;
					BoundImportNameLenth = i;
					break;
				}
				else {
					if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
						break;
					}
				}
			}
			if (IsBoundImport) {
				UCHAR BoundImportModuleName[160];
				RtlZeroMemory(BoundImportModuleName, sizeof(BoundImportModuleName));
				memcpy(BoundImportModuleName, FunAddress, BoundImportNameLenth);

				LPCSTR BoundImportFunctionName = (LPCSTR)(FunAddress + BoundImportNameLenth + 1);
				ULONG64 base = (ULONG64)KGetDriverImageBase2((PCHAR)BoundImportModuleName);
				if (base) {
					return KGetProcAddress((PVOID)base, BoundImportFunctionName);
				}
				

			}

			return FunAddress;
		}

	}

	return NULL;
}

PVOID64 KGetPteBase_Signature() {
	DWORD64 Ntoskrnl = (DWORD64)KGetNtoskrnl();
	DWORD64 Fun = (DWORD64)KGetProcAddress((PVOID)Ntoskrnl, "MmGetVirtualForPhysical");
	DWORD64 pos = FindSignatureCode_nocheck((LPCVOID)Fun, 0x200, "48BA????????????????48C1E219", 0);
	if (pos == -1)return NULL;
	return *(PVOID64 *)(pos + Fun + 2);
}
PVOID64 KGetPteBase() {
	ULONG BuildNumber = KGetBuildNumber();
	ULONG64 pte_base = 0;
	if (BuildNumber < 14316) {
		//win10
		pte_base = 0xFFFFF68000000000;
	}
	else {
		ULONG64 cr3_mask = ~(ULONG64)0xFFF;
		ULONG64 cr3 = __readcr3() & cr3_mask;
		PHYSICAL_ADDRESS phy;
		phy.QuadPart = cr3;
		ULONG64 vir = (ULONG64)MmGetVirtualForPhysical(phy);
		if (vir) {
			for (int i = 0; i < 0x200; i++) {
				HardwarePteX64 v;
				v.all = *(ULONG64*)(vir + i * 8);
				if ((v.page_frame_number << 12) == cr3) {
					ULONG64 addon = (ULONG64)i << 39;
					pte_base = 0xFFFF000000000000 | addon;
					break;
				}
			}
		}
		else {
			pte_base = (ULONG64)KGetPteBase_Signature();
		}


	}
	return (PVOID64)pte_base;

}
BOOL KIsAddressValid(PVOID Address) {
	return MmiGetPhysicalAddress(Address) != 0;
}
VOID KRaiseIrqlToDpcOrHigh(PIRQL_STATE state) {
	state->old_irql = __readcr8();
	if (state->old_irql < DISPATCH_LEVEL) {
		__writecr8(DISPATCH_LEVEL);
	}
}
VOID KLowerIrqlToState(PIRQL_STATE state) {
	if (state->old_irql < DISPATCH_LEVEL) {
		__writecr8(state->old_irql);
	}
}
