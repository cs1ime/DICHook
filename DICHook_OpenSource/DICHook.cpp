//author :cslime
//https://github.com/CS1ime/DICHook

#include "DDKCommon.h"
#include "DICHook.h"
#include "ntddndis.h"
#include "kernelasm.h"
#include "ntifs.h"
#include "NtFunctionDefine.h"
#include "MyPEB.h"

#define printf 

typedef struct _HOOK_DEVICE_IO_CONTEXT {
	PVOID JmpPage;
	PVOID Object;
	ULONG64 iosb;
	ULONG IoControlCode;
	ULONG64 InputBuffer;
	ULONG InputBufferLength;
	ULONG64 OutputBuffer;
	ULONG OutputBufferLength;
}HOOK_DEVICE_IO_CONTEXT;
typedef struct _HOOK_NTQUERY_CONTEXT {
	PVOID JmpPage;
	ULONG FsInformationClass;
	ULONG64 FsInformation;
	ULONG Length;
}HOOK_NTQUERY_CONTEXT;

typedef BOOL(*fnIoCtlPostCallback)(HOOK_DEVICE_IO_CONTEXT *);
fnIoCtlPostCallback g_IoCtlPostCallback = 0;

typedef void(*fndiccabk)(ULONG64, ULONG64, ULONG64, ULONG64, ULONG64);
typedef void(*fnntqcabk)(ULONG64, ULONG64, ULONG64);
typedef VOID(*fnExtraCallback)(VOID);
fndiccabk dicpostcabk = 0;
fndiccabk dicprecabk = 0;
fnntqcabk ntqcabk = 0;
fnExtraCallback pcabk = 0;

#include "vtstruct.h"

ULONG64 Search_FsInformation = 0;
ULONG Search_Length = 0;
ULONG64 Search_Object = 0;

ULONG64 pRetCodePage = 0;
ULONG64 pNtQueryRetCodePage = 0;

ULONG64 NtDeviceIoControlFileRet = 0;
ULONG64 NtFsControlFileRet = 0;
ULONG64 NtQueryVolumeInformationFileRet = 0;

ULONG RspOffset = 0;
ULONG RspOffset_NtQuery = 0;

ULONG NtDevice_Offset_Object = 0;

ULONG NtQuery_StackSize = 0;
LONG NtQuery_Offset_FsInformation = 0;
LONG NtQuery_Offset_Length = 0;

ULONG64 MyAllocEx() {
	return 0;
}
VOID TestDeviceIoControl() {
	HANDLE FileHandle = 0;
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"\\??\\C:");

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, 0, 0);
	IO_STATUS_BLOCK iosb;
	RtlZeroMemory(&iosb, sizeof(IO_STATUS_BLOCK));
	NTSTATUS stats = ZwCreateFile(&FileHandle, FILE_GENERIC_READ, &oa, &iosb, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 0, 0);
	RtlZeroMemory(&iosb, sizeof(IO_STATUS_BLOCK));

	PFILE_OBJECT obj = 0;
	OBJECT_HANDLE_INFORMATION objhandle = { 0 };
	RtlZeroMemory(&objhandle, sizeof(objhandle));
	stats = ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, KernelMode, (PVOID *)&obj, &objhandle);
	if (!NT_SUCCESS(stats)) {
		ZwClose(FileHandle);
		KeBugCheck(0x56009);
	}
	ObDereferenceObject(obj);
	Search_Object = (ULONG64)obj;
	typedef NTSTATUS
	(*NTAPI fnNtDeviceIoControlFile)(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG IoControlCode,
		_In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
		_In_ ULONG InputBufferLength,
		_Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
		_In_ ULONG OutputBufferLength
		);
	fnNtDeviceIoControlFile pNtDeviceIoControlFile = (fnNtDeviceIoControlFile)KGetProcAddress(KGetNtoskrnl(), "NtDeviceIoControlFile");
	UCHAR Input[4] = { 0 };
	UCHAR Output[4] = { 0 };
	ULONG64 Magic[2];
	Magic[0] = 0x1122334455667788;
	Magic[1] = 0x8877665544772299;
	pNtDeviceIoControlFile(FileHandle, 0, 0, 0, &iosb, IOCTL_NDIS_QUERY_GLOBAL_STATS, Input, 4, Output, 4);

	ZwClose(FileHandle);
}
VOID TestNtQueryVolumeInformationFile() {
	HANDLE FileHandle = 0;
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"\\??\\C:");

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, 0, 0);
	IO_STATUS_BLOCK iosb;
	RtlZeroMemory(&iosb, sizeof(IO_STATUS_BLOCK));

	NTSTATUS stats = ZwCreateFile(&FileHandle, FILE_GENERIC_READ, &oa, &iosb, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 0, 0);
	RtlZeroMemory(&iosb, sizeof(IO_STATUS_BLOCK));
	FILE_FS_OBJECTID_INFORMATION *pinfo = (FILE_FS_OBJECTID_INFORMATION *)ExAllocatePoolWithTag(NonPagedPoolNx, 0x2000, POOL_TAG);
	RtlZeroMemory(pinfo, sizeof(FILE_FS_OBJECTID_INFORMATION));

	ULONG64 Mark[2];
	Mark[0] = 0xCC22334455666688;
	Mark[1] = 0xAA77665544333399;

	Search_FsInformation = (ULONG64)pinfo;
	Search_Length = 0x1238;
	NtQueryVolumeInformationFile(FileHandle, &iosb, pinfo, 0x1238, FileFsObjectIdInformation);
	ExFreePoolWithTag(pinfo, POOL_TAG);
	ZwClose(FileHandle);
}

ULONG64 GetIopDispatchAllocateIrp() {
	ULONG BuildNumber = KGetBuildNumber();
	if (BuildNumber >= 15063) {
		//8B 05 ?? ?? ?? ?? 44 8A C2
		ULONG64 pos = ScanSection(".text", "8B05????????448AC2");
		if (pos) {
			return *(LONG *)(pos + 2) + pos + 6;
		}
		else {
			pos = ScanSection(".text", "8B05????????440FB6C2");
			if (pos) {
				return *(LONG *)(pos + 2) + pos + 6;
			}
		}
	}
	return 0;
}
BOOL InitStackSize() {
	ULONG64 ntos = (ULONG64)KGetNtoskrnl();

	ULONG64 pNtQueryVolumeInformationFile = (ULONG64)KGetProcAddress((PVOID)ntos, "NtQueryVolumeInformationFile");

	//63 ?? 24 ?? ?? 00 00
	ULONG64 pos = FindSignatureCode_nocheck((LPCVOID)pNtQueryVolumeInformationFile, 0x200, "63??24????0000", 0);
	if (pos == -1)return FALSE;
	NtQuery_StackSize = *(ULONG *)(pos + pNtQueryVolumeInformationFile + 3) - 0x28;



	return TRUE;
}

namespace DispatchControl {
	BOOLEAN enable_ntq = TRUE;
	BOOLEAN enable = FALSE;
	BOOLEAN Inited = FALSE;
}
VOID DispatchCallback(ULONG64 pRsp) {
	static const unsigned char shellcode[] = "\x48\xB9\x00\x00\x00\x00\x00\x10\x00\x00\x51\x48\xB9\x00\x00\x00\x00\x00\x10\x00\x00\x50\xC7\x04\x24\x00\x00\x00\x10\xC7\x44\x24\x04\x00\x00\x00\x10\xC3"
		;
	KIRQL irql = AsmReadCr8() & 0xFF;
	if (irql >= DISPATCH_LEVEL)return;
	ULONG64 RFlag = AsmGetRFlags();
	if (RFlag & 0x10000) {
		return;
	}
	int Pid = (int)PsGetProcessId(PsGetCurrentThreadProcess());
	if ((int)Pid != 4) {
		if (pcabk) {
			pcabk();
			
		}
	}
	ULONG64 Low = 0, High = 0;
	IoGetStackLimits(&Low, &High);
	if (DispatchControl::Inited == FALSE) {
		if (RspOffset == 0 || DispatchControl::enable_ntq ? RspOffset_NtQuery == 0 : false) {
			PULONG64 Rsp = (PULONG64)pRsp;
			for (int i = 0; (ULONG64)Rsp < High - 8; Rsp++, i++) {
				if (RspOffset == 0) {
					if (Rsp[0] == 0x1122334455667788) {
						if (Rsp[1] == 0x8877665544772299) {
							//搜索栈上Object偏移
							ULONG64 OLRSP = (ULONG64)Rsp;
							for (int j = 0; OLRSP > pRsp && j < 0x1000; OLRSP -= 8, j += 8) {
								if (*(ULONG64*)OLRSP == NtDeviceIoControlFileRet) {
									RspOffset = OLRSP - pRsp;
									//printf("[112233] RspOffset %x\n", RspOffset);
									ULONG64 OOLRSP = OLRSP;
									for (int p = 0; OOLRSP > pRsp && p < 0x1000; OOLRSP -= 8, p += 8) {
										//search arg offset
										if (NtDevice_Offset_Object)
											break;
										if (NtDevice_Offset_Object == 0) {
											if (*(ULONG64*)OOLRSP == Search_Object) {
												NtDevice_Offset_Object = OOLRSP - pRsp;
												continue;
											}
										}

									}
									break;
								}
							}
						}
					}
					if (RspOffset)break;
				}
				if (RspOffset_NtQuery == 0 && DispatchControl::enable_ntq) {
					if (Rsp[0] == 0xCC22334455666688) {
						if (Rsp[1] == 0xAA77665544333399) {
							//搜索栈上参数偏移
							ULONG64 OLRSP = (ULONG64)Rsp;
							for (int j = 0; OLRSP > pRsp && j < 0x800; OLRSP -= 8, j += 8) {
								if (*(ULONG64*)OLRSP == NtQueryVolumeInformationFileRet) {
									RspOffset_NtQuery = OLRSP - pRsp;
									ULONG64 OOLRSP = OLRSP;
									for (int p = 0; OOLRSP > pRsp && p < 0x800; OOLRSP -= 8, p += 8) {
										//search arg offset
										if (NtQuery_Offset_FsInformation && NtQuery_Offset_Length)
											break;
										if (NtQuery_Offset_FsInformation == 0) {
											if (*(ULONG64*)OOLRSP == Search_FsInformation) {
												NtQuery_Offset_FsInformation = OOLRSP - pRsp;
												continue;
											}
										}
										if (NtQuery_Offset_Length == 0) {
											if (*(ULONG*)OOLRSP == Search_Length) {
												NtQuery_Offset_Length = OOLRSP - pRsp;
												continue;
											}
										}

									}
									//搜不到就蓝屏
									if (NtQuery_Offset_Length == 0) {
										KeBugCheck(0x33221);
									}
									if (NtQuery_Offset_FsInformation == 0) {
										KeBugCheck(0x33222);
									}
									break;
								}
							}
							printf("[112233] RspOffset_NtQuery:%x\n", RspOffset_NtQuery);
							printf("[112233] FsInformation:%x Length:%x\n", NtQuery_Offset_FsInformation, NtQuery_Offset_Length);
						}
					}
					if (RspOffset_NtQuery)break;
				}

			}
			//printf("[112233] RspOffset:%x RspOffset_Ntquery:%x\n", RspOffset, RspOffset_NtQuery);
		}
	}

	if (RspOffset) {
		if (High - pRsp > RspOffset) {
			if (*(ULONG64 *)(pRsp + RspOffset) == NtDeviceIoControlFileRet || *(ULONG64*)(pRsp + RspOffset) == NtFsControlFileRet) {
				ULONG64 LRSP = (ULONG64)(pRsp + RspOffset);

				ULONG64 Object = *(ULONG64 *)(pRsp + NtDevice_Offset_Object);
				ULONG64 iosb = *(ULONG64*)(LRSP + 8 + 0x90);
				ULONG ControlCode = *(ULONG *)(LRSP + 8 + 0x98);
				ULONG64 InputBuffer = *(ULONG64 *)(LRSP + 8 + 0xA0);
				ULONG InputBufferLength = *(ULONG *)(LRSP + 8 + 0xA8);
				ULONG64 OutputBuffer = *(ULONG64 *)(LRSP + 8 + 0xB0);
				ULONG OutputBufferLength = *(ULONG *)(LRSP + 8 + 0xB8);

				HOOK_DEVICE_IO_CONTEXT lContext;
				RtlZeroMemory(&lContext, sizeof(lContext));
				lContext.iosb = iosb;
				lContext.InputBuffer = InputBuffer;
				lContext.InputBufferLength = InputBufferLength;
				lContext.OutputBuffer = OutputBuffer;
				lContext.OutputBufferLength = OutputBufferLength;
				lContext.IoControlCode = ControlCode;
				lContext.Object = (PVOID)Object;

				if (g_IoCtlPostCallback(&lContext)) {
					HOOK_DEVICE_IO_CONTEXT *Context = (HOOK_DEVICE_IO_CONTEXT *)ExAllocatePool(NonPagedPoolNx, sizeof(lContext));
					RtlZeroMemory(Context, sizeof(HOOK_DEVICE_IO_CONTEXT));
					memcpy(Context, &lContext, sizeof(lContext));
					PUCHAR JmpPage = (PUCHAR)ExAllocatePool(NonPagedPool, sizeof(shellcode)+1);
					memcpy(JmpPage, shellcode, sizeof(shellcode));
					ULONG offset = 0;
					*(ULONG64 *)(JmpPage + 0x2 + offset) = *(ULONG64 *)(LRSP + 0x70);
					*(ULONG64 *)(JmpPage + 0xd + offset) = (ULONG64)Context;
					LARGE_INTEGER Addr;
					Addr.QuadPart = pRetCodePage;
					*(ULONG *)(JmpPage + 0x19 + offset) = Addr.LowPart;
					*(ULONG *)(JmpPage + 0x21 + offset) = Addr.HighPart;

					Context->JmpPage = JmpPage;
					*(ULONG64 *)(LRSP + 0x70) = (ULONG64)JmpPage;
				}
				
				return;
			}
		}
	}
	if (RspOffset_NtQuery && DispatchControl::enable_ntq) {
		if (High - pRsp > RspOffset_NtQuery) {
			if (*(ULONG64 *)(pRsp + RspOffset_NtQuery) == NtQueryVolumeInformationFileRet) {
				ULONG64 LRSP = (ULONG64)(pRsp + RspOffset_NtQuery);
				ULONG FsInfomationClass = *(ULONG *)(LRSP + 8 + NtQuery_StackSize + 0x28);
				ULONG64 FsInformation = *(ULONG64 *)(pRsp + NtQuery_Offset_FsInformation);
				ULONG Length = *(ULONG *)(pRsp + NtQuery_Offset_Length);

				printf("[112233] NtQ Class %d FsInfomation %p Length %x\n", FsInfomationClass, FsInformation, Length);

				HOOK_NTQUERY_CONTEXT* Context = (HOOK_NTQUERY_CONTEXT*)ExAllocatePool(NonPagedPoolNx, sizeof(HOOK_NTQUERY_CONTEXT));
				RtlZeroMemory(Context, sizeof(HOOK_NTQUERY_CONTEXT));

				Context->FsInformation = FsInformation;
				Context->FsInformationClass = FsInfomationClass;
				Context->Length = Length;

				PUCHAR JmpPage = (PUCHAR)ExAllocatePool(NonPagedPool, sizeof(shellcode)+1);
				memcpy(JmpPage, shellcode, sizeof(shellcode));
				ULONG offset = 0;
				*(ULONG64 *)(JmpPage + 0x2 + offset) = *(ULONG64 *)(LRSP + 8 + NtQuery_StackSize);
				*(ULONG64 *)(JmpPage + 0xd + offset) = (ULONG64)Context;
				LARGE_INTEGER Addr;
				Addr.QuadPart = pNtQueryRetCodePage;
				*(ULONG *)(JmpPage + 0x19 + offset) = Addr.LowPart;
				*(ULONG *)(JmpPage + 0x21 + offset) = Addr.HighPart;

				Context->JmpPage = JmpPage;

				*(ULONG64 *)(LRSP + 8 + NtQuery_StackSize) = (ULONG64)JmpPage;
			}
		}
	}


	return;
}

BOOLEAN g_hooked = FALSE;

VOID InstallHook(fnIoCtlPostCallback PostCallback, PVOID PreCallback, PVOID NtQueryPre) {
	if (g_hooked == TRUE) {
		return;
	}

	static unsigned char shellcode[] = "\x50\x53\x51\x52\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9C\x48\x8D\x8C\x24\x80\x00\x00\x00\x48\xB8\x00\x00\x00\x00\x00\x01\x00\x00\x48\x35\xFF\xFF\xFF\x7F\x48\x93\xE8\x30\x00\x00\x00\xFF\xD3\xE8\x3E\x00\x00\x00\x9D\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5D\x5F\x5E\x5A\x59\x5B\x58\x50\xC7\x04\x24\x00\x00\x00\x10\xC7\x44\x24\x04\x00\x00\x00\x10\xC3\x4C\x8D\x5C\x24\x08\x48\x83\xE4\xF0\x41\x53\x41\x53\x48\x83\xEC\x30\x41\xFF\x63\xF8\x41\x5B\x48\x83\xC4\x38\x5C\x41\xFF\xE3"
		;
	static unsigned char shellcode2[] = "\x50\x53\x51\x52\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9C\x48\xB8\x00\x00\x00\x00\x00\x01\x00\x00\x48\x35\xFF\xFF\xFF\x7F\x48\x93\xE8\x20\x00\x00\x00\xFF\xD3\xE8\x2E\x00\x00\x00\x9D\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5D\x5F\x5E\x5A\x59\x5B\x58\xC3\x4C\x8D\x5C\x24\x08\x48\x83\xE4\xF0\x41\x53\x41\x53\x48\x83\xEC\x30\x41\xFF\x63\xF8\x41\x5B\x48\x83\xC4\x38\x5C\x41\xFF\xE3"
		;
	static unsigned char shellcode3[] = "\x50\x53\x51\x52\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9C\x48\x89\xC2\x48\xB8\x00\x00\x00\x00\x01\x00\x00\x00\x48\x35\xFF\xFF\xFF\x7F\x48\x93\xE8\x20\x00\x00\x00\xFF\xD3\xE8\x2E\x00\x00\x00\x9D\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5D\x5F\x5E\x5A\x59\x5B\x58\xC3\x4C\x8D\x5C\x24\x08\x48\x83\xE4\xF0\x41\x53\x41\x53\x48\x83\xEC\x30\x41\xFF\x63\xF8\x41\x5B\x48\x83\xC4\x38\x5C\x41\xFF\xE3"
		;
	static unsigned char shellcode4[] = "\x53\x51\x52\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9C\x48\x89\xC2\x48\xB8\x00\x00\x00\x00\x01\x00\x00\x00\x48\x35\xFF\xFF\xFF\x7F\x48\x93\xE8\x1F\x00\x00\x00\xFF\xD3\xE8\x2D\x00\x00\x00\x9D\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5D\x5F\x5E\x5A\x59\x5B\xC3\x4C\x8D\x5C\x24\x08\x48\x83\xE4\xF0\x41\x53\x41\x53\x48\x83\xEC\x30\x41\xFF\x63\xF8\x41\x5B\x48\x83\xC4\x38\x5C\x41\xFF\xE3"
		;

	if (!InitStackSize())KeBugCheck(0x897877);
	ULONG BuildNumber = KGetBuildNumber();
	ULONG64 ntos = (ULONG64)KGetNtoskrnl();

	ULONG64 ViPacketLookaside = 0;
	//ViPacketLookaside
	//48 8B F9 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C9
	//48 8D 0D ?? ?? ?? ?? 66 89 74 24 ?? 41 B9 00 02 00 00 C7 44 24 ?? 49 72 70 74
	//48 8B D3 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? F0 FF 0D 
	ULONG64 pos = ScanSection("PAGEVRFY", "488BF9488D0D????????E8????????33C9");
	if (pos) {
		ViPacketLookaside = *(LONG*)(pos + 6) + pos + 10;
	}
	else {
		pos = ScanSection("PAGEVRFY", "48 8D 0D ?? ?? ?? ?? 66 89 74 24 ?? 41 B9 00 02 00 00 C7 44 24 ?? 49 72 70 74");
		if (pos) {
			ViPacketLookaside = *(LONG*)(pos + 3) + pos + 7;
		}
		else {
			pos = ScanSection("PAGEVRFY", "48 8B D3 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? F0 FF 0D");
			if (pos) {
				ViPacketLookaside = *(LONG*)(pos + 6) + pos + 10;
			}
		}
	}
	if (!ViPacketLookaside) {
		KeBugCheck(0x957778);
	}
	//DbgPrint("[112233] ViPacketLookaside %p\n", ViPacketLookaside);
	//48 8D 0D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 E8

	if (*(ULONG64 *)(ViPacketLookaside + 0x30) == 0) {
		pos = ScanSection("PAGEVRFY", "488D0D????????C705????????01000000E8");
		if (!pos) {
			pos = ScanSection("PAGE", "488D0D????????C705????????01000000E8");
			if (!pos)KeBugCheck(0x957776);
		}
		ULONG64 VfInitVerifierComponents = *(LONG *)(pos + 3) + pos + 7;
		typedef ULONG64(*fnVfInitVerifierComponents)(ULONG64, ULONG64, ULONG64);
		fnVfInitVerifierComponents v = (fnVfInitVerifierComponents)VfInitVerifierComponents;
		v(0, 0, 0);
	}
	ULONG64 VfIoDisabled = 0;
	if (BuildNumber < 10240) {
		//win7 8B 05 ?? ?? ?? ?? 33 FF 49 8B F1
		pos = ScanSection("PAGEVRFY", "8B05????????33FF498BF1");
		if (!pos) KeBugCheck(0x6765544);
		VfIoDisabled = *(LONG *)(pos + 2) + pos + 6;
	}
	else {
		//8B 05 ?? ?? ?? ?? 40 FE C5
		pos = ScanSection("PAGEVRFY", "8B05????????40FEC5");
		if (!pos)  KeBugCheck(0x6765544);
		VfIoDisabled = *(LONG *)(pos + 2) + pos + 6;
	}
	ULONG64 IovAllocateIrp = 0;
	ULONG64 pIoAllocateIrp = 0;
	ULONG64 IopDispatchAllocateIrp = 0;
	if (BuildNumber < 10240) {
		//48 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 05
		pos = ScanSection("PAGEVRFY", "488D05????????488D15????????488905");
		if (!pos) KeBugCheck(0x6725544);
		IovAllocateIrp = *(LONG *)(pos + 3) + pos + 7;
		pIoAllocateIrp = *(LONG *)(pos + 17) + pos + 21;
		*(ULONG64 *)(pIoAllocateIrp) = IovAllocateIrp;

	}
	else if (BuildNumber >= 10240 && BuildNumber <= 14393) {
		//48 8D 05 ?? ?? ?? ?? 48 87 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 87 0D ?? ?? ?? ?? 48 8D 05 
		pos = ScanSection(".text", "488D05????????488705????????488D0D????????48870D????????488D05");
		if (!pos) KeBugCheck(0x6725544);
		IovAllocateIrp = *(LONG *)(pos + 3) + pos + 7;
		pIoAllocateIrp = *(LONG *)(pos + 10) + pos + 14;

		*(ULONG64 *)(pIoAllocateIrp) = IovAllocateIrp;
	}
	else if (BuildNumber >= 15063) {
		//87 05 ?? ?? ?? ?? 87 0D
		pos = ScanSection(".text", "8705????????870D");
		if (!pos) KeBugCheck(0x6725544);
		IopDispatchAllocateIrp = *(LONG *)(pos + 2) + pos + 6;
		//if (!IopDispatchAllocateIrp)return;
		*(int *)(IopDispatchAllocateIrp) = 1;
	}

	ULONG bn = KGetBuildNumber();

	//搜索调用NtDeviceIoControlFile的时候堆栈中会出现的返回地址
	//E8 ?? ?? ?? ?? 48 8B D8 48 89 84 24 ?? ?? ?? ?? 48 85 C0
	//E8 ?? ?? ?? ?? 48 83 C4
	ULONG64 pNtDeviceIoControlFile = (ULONG64)KGetProcAddress((PVOID)ntos, "NtDeviceIoControlFile");
	pos = FindSignatureCode_nocheck((LPCVOID)pNtDeviceIoControlFile, 0x200, "E8????????4883C4", 0);
	if (pos == -1)KeBugCheck(0x89997);
	NtDeviceIoControlFileRet = pos + pNtDeviceIoControlFile + 5;

	ULONG64 pNtFsControlFile = (ULONG64)KGetProcAddress((PVOID)ntos, "NtFsControlFile");
	pos = FindSignatureCode_nocheck((LPCVOID)pNtFsControlFile, 0x200, "E8????????4883C4", 0);
	if (pos == -1)KeBugCheck(0x89998);
	NtFsControlFileRet = pos + pNtFsControlFile + 5;
	//printf("[112233] NtDeviceIoControlFileRet %p\n", NtDeviceIoControlFileRet);
	//printf("[112233] NtFsControlFileRet %p\n", NtFsControlFileRet);

	//搜索调用NtQueryVolumeInformationFile的时候堆栈中会出现的返回地址
	//NtQueryVolumeInformationFileRet
	ULONG64 pNtQueryVolumeInformationFile = (ULONG64)KGetProcAddress((PVOID)ntos, "NtQueryVolumeInformationFile");
	if (BuildNumber < WIN10_1507) {
		//4C E8 ?? ?? ?? ?? 48
		pos = FindSignatureCode_nocheck((LPCVOID)pNtQueryVolumeInformationFile, 0x1000, "4CE8????????48", 0);
		if (pos == -1)KeBugCheck(0x89967);
		NtQueryVolumeInformationFileRet = pos + pNtQueryVolumeInformationFile + 6;
	}
	else if (BuildNumber >= WIN10_1507 && BuildNumber <= WIN10_1607) {
		//4C ?? ?? ?? FF 15 ?? ?? ?? ?? ?? ?? ?? 48
		pos = FindSignatureCode_nocheck((LPCVOID)pNtQueryVolumeInformationFile, 0x1000, "4C??????FF15??????????????48", 0);
		if (pos == -1)KeBugCheck(0x89967);
		NtQueryVolumeInformationFileRet = pos + pNtQueryVolumeInformationFile + 10;
	}
	else if (BuildNumber >= WIN10_1703) {
		//4C ?? 8B ?? E8 ?? ?? ?? ?? ?? 89
		//4C ?? 8B ?? E8 ?? ?? ?? ?? ?? 8B ?? 48 89 44 24
		//4C E8 ?? ?? ?? ?? ?? 8B ?? 48 89 44 24
		//4C ?? 8B ?? E8 ?? ?? ?? ?? 48 89 44 24

		pos = FindSignatureCode_nocheck((LPCVOID)pNtQueryVolumeInformationFile, 0x1000, "4C ?? 8B ?? E8 ?? ?? ?? ?? ?? 89", 0);
		if (pos != -1) {
			NtQueryVolumeInformationFileRet = pos + pNtQueryVolumeInformationFile + 9;
		}
		else {
			pos = FindSignatureCode_nocheck((LPCVOID)pNtQueryVolumeInformationFile, 0x600, "4C ?? 8B ?? E8 ?? ?? ?? ?? ?? 8B ?? 48 89 44 24", 0);
			if (pos != -1) {
				NtQueryVolumeInformationFileRet = pos + pNtQueryVolumeInformationFile + 9;
			}
			else {
				pos = FindSignatureCode_nocheck((LPCVOID)pNtQueryVolumeInformationFile, 0x800, "4C E8 ?? ?? ?? ?? ?? 8B ?? 48 89 44 24", 0);
				if (pos != -1) {
					NtQueryVolumeInformationFileRet = pos + pNtQueryVolumeInformationFile + 6;
				}
				else {
					KeBugCheck(0x89967);
				}
			}

		}
	}
	//DbgPrint("[112233] NtQueryVolumeInformationFile %p\n", pNtQueryVolumeInformationFile);
	//DbgPrint("[112233] NtQueryVolumeInformationFileRet %p\n", NtQueryVolumeInformationFileRet);

	if (!NtQueryVolumeInformationFileRet)
		KeBugCheck(0x89967);
	if (BuildNumber < 10240) {
		*(ULONG64*)(pIoAllocateIrp) = IovAllocateIrp;
	}
	else if (BuildNumber >= 10240 && BuildNumber <= 14393) {
		*(ULONG64*)(pIoAllocateIrp) = IovAllocateIrp;
	}
	else if (BuildNumber >= 15063) {
		*(int*)(IopDispatchAllocateIrp) = 1;
	}
	
	KIRQL irql = KeRaiseIrqlToDpcLevel();

	pRetCodePage = (ULONG64)ExAllocatePool(NonPagedPool, 0x500);
	memcpy((PVOID)pRetCodePage, shellcode2, sizeof(shellcode2));
	*(ULONG64*)(pRetCodePage + 0x1A) = ((ULONG64)PreCallback) ^ 0x7fffffff;

	pNtQueryRetCodePage = (ULONG64)ExAllocatePool(NonPagedPool, 0x500);
	memcpy((PVOID)pNtQueryRetCodePage, shellcode3, sizeof(shellcode3));
	*(ULONG64*)(pNtQueryRetCodePage + 0x1D) = ((ULONG64)NtQueryPre) ^ 0x7fffffff;
	g_IoCtlPostCallback = PostCallback;

	PUCHAR pcode = (PUCHAR)ExAllocatePool(NonPagedPool, 0x500);
	memcpy(pcode, shellcode, sizeof(shellcode));
	*(ULONG64 *)(pcode + 0x22) = ((ULONG64)DispatchCallback) ^ 0x7fffffff;

	//修改ViPacketLookaside.AllocEx
	ULONG64 pfn = *(ULONG64*)(ViPacketLookaside + 0x30);
	
	LARGE_INTEGER Addr;
	Addr.QuadPart = (ULONG64)MyAllocEx;
	*(ULONG *)(pcode + 0x5A) = Addr.LowPart;
	*(ULONG *)(pcode + 0x62) = Addr.HighPart;
	InterlockedExchange64((volatile LONG64*)(ViPacketLookaside + 0x30), (LONG64)pcode);

	*(DWORD*)(pcode + sizeof(shellcode)) = 0xDEADBEEF;

	*(int*)(VfIoDisabled) = 0;
	
	KeLowerIrql(irql);
	TestDeviceIoControl();
	TestNtQueryVolumeInformationFile();


	DispatchControl::Inited = TRUE;
}
BOOL FnDICPostCallback(HOOK_DEVICE_IO_CONTEXT *Context) {

	if (Context) {
		PFILE_OBJECT FileObject = (PFILE_OBJECT)Context->Object;
		if (dicpostcabk) {
			dicpostcabk(Context->IoControlCode, Context->InputBuffer, Context->InputBufferLength, Context->OutputBuffer, Context->OutputBufferLength);
		}
		return TRUE;
	}
	return FALSE;
}
VOID FnDICPreCallback(HOOK_DEVICE_IO_CONTEXT *aContext){
	if (aContext) {
		HOOK_DEVICE_IO_CONTEXT Context = *aContext;
		ExFreePool(Context.JmpPage);
		ExFreePool(aContext);
		if (dicprecabk) {
			dicprecabk(Context.IoControlCode, Context.InputBuffer, Context.InputBufferLength, Context.OutputBuffer, Context.OutputBufferLength);
		}
	}
}
VOID FnNtQueryPreCallback(HOOK_NTQUERY_CONTEXT *aContext) {
	if (aContext) {
		HOOK_NTQUERY_CONTEXT Context = *aContext;
		ExFreePool(Context.JmpPage);
		ExFreePool(aContext);
		
		if (ntqcabk) {
			ntqcabk(Context.FsInformationClass, Context.FsInformation, Context.Length);
		}
	}
}

BOOL DICPostCallback(HOOK_DEVICE_IO_CONTEXT* Context) {
	//提升irql至2,关闭smap
	IRQL_STATE state;
	KRaiseIrqlToDpcOrHigh(&state);
	Cr4 cr4;
	cr4.all = __readcr4();
	bool smap = cr4.fields.smap == 1;
	if (smap) {
		cr4.fields.smap = 0;
		__writecr4(cr4.all);
	}
	BOOL ret = FnDICPostCallback(Context);
	if (smap) {
		cr4.fields.smap = 1;
		__writecr4(cr4.all);
	}
	KLowerIrqlToState(&state);
	return ret;
}
VOID DICPreCallback(HOOK_DEVICE_IO_CONTEXT* aContext) {
	//提升irql至2,关闭smap
	IRQL_STATE state;
	KRaiseIrqlToDpcOrHigh(&state);
	Cr4 cr4;
	cr4.all = __readcr4();
	bool smap = cr4.fields.smap == 1;
	if (smap) {
		cr4.fields.smap = 0;
		__writecr4(cr4.all);
	}
	FnDICPreCallback(aContext);
	if (smap) {
		cr4.fields.smap = 1;
		__writecr4(cr4.all);
	}
	KLowerIrqlToState(&state);
}
VOID NtQueryPreCallback(HOOK_NTQUERY_CONTEXT* aContext) {
	//提升irql至2,关闭smap
	IRQL_STATE state;
	KRaiseIrqlToDpcOrHigh(&state);
	Cr4 cr4;
	cr4.all = __readcr4();
	bool smap = cr4.fields.smap == 1;
	if (smap) {
		cr4.fields.smap = 0;
		__writecr4(cr4.all);
	}
	FnNtQueryPreCallback(aContext);
	if (smap) {
		cr4.fields.smap = 1;
		__writecr4(cr4.all);
	}
	KLowerIrqlToState(&state);
}

VOID setpcabk(PVOID fun) {
	pcabk = (fnExtraCallback)fun;
	InstallHook(DICPostCallback, DICPreCallback, NtQueryPreCallback);
}
VOID setdicpostcabk(PVOID func) {
	dicpostcabk = (fndiccabk)func;
	InstallHook(DICPostCallback, DICPreCallback, NtQueryPreCallback);
}
VOID setdicprecabk(PVOID func) {
	dicprecabk = (fndiccabk)func;
	InstallHook(DICPostCallback, DICPreCallback, NtQueryPreCallback);
}
VOID setntqcabk(PVOID func) {
	ntqcabk = (fnntqcabk)func;
}

VOID setntqhookstats(BOOL stats) {
	DispatchControl::enable_ntq = stats;
}
