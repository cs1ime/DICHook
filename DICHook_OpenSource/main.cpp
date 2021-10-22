//author :cslime
//https://github.com/CS1ime/DICHook

#include "DDKCommon.h"
#include "MyMemoryIo64.h"
#include "DICHook.h"
#include <ntddndis.h>

VOID NtDeviceIoControlFileCallback(ULONG64 pObject, ULONG64 IoControlCode, ULONG64 InputBuffer, ULONG64 InputBufferLength, ULONG64 OutputBuffer, ULONG64 OutputBufferLength) {
	//此时irql == 2 !
	// 
	//修改物理Mac地址例子
	if (IoControlCode == IOCTL_NDIS_QUERY_GLOBAL_STATS &&
		InputBufferLength >= 4 && MmiGetPhysicalAddress((PVOID)InputBuffer) && MmiGetPhysicalAddress((PVOID)(InputBuffer + 4 - 1)) &&
		OutputBufferLength >= 6 && MmiGetPhysicalAddress((PVOID)OutputBuffer) && MmiGetPhysicalAddress((PVOID)(OutputBuffer + 6 - 1))) {
		DWORD Code = *(DWORD*)(InputBuffer);
		switch (Code) {
			case OID_802_3_PERMANENT_ADDRESS:
			case OID_802_3_CURRENT_ADDRESS:
			case OID_802_5_PERMANENT_ADDRESS:
			case OID_802_5_CURRENT_ADDRESS:
			{
				PUCHAR pMac = (PUCHAR)OutputBuffer;
				pMac[0] = 0x00; pMac[1] = 0x11; pMac[2] = 0x22; pMac[3] = 0x33; pMac[4] = 0x44; pMac[5] = 0x55;
				break;
			}
			default:
				break;
		}
	}
}
VOID NtQueryVolumeInformationFileCallback(ULONG64 FsInformationClass, ULONG64 FsInformation, ULONG64 Length) {
	//此时irql == 2 !
	// 
	//修改分区序列号例子
	
	//
	switch (FsInformationClass)
	{ 
	case FileFsVolumeInformation:
	{
		if (Length >= sizeof(FILE_FS_VOLUME_INFORMATION) && 
			MmiGetPhysicalAddress((PVOID)FsInformation) && 
			MmiGetPhysicalAddress((PVOID)(FsInformation + sizeof(FILE_FS_VOLUME_INFORMATION) - 1))) {

			PFILE_FS_VOLUME_INFORMATION pinfo = (PFILE_FS_VOLUME_INFORMATION)FsInformation;
			pinfo->VolumeSerialNumber = 0;
		}
		break;
	}
	default:
		break;
	}
}
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg_path) {
	Mmi_Init();

	//设置是否启用 NtQueryVolumeInformationFile Hook,TRUE为开启,FALSE为关闭
	//注意,win10 1507 - win10 1709不支持NtQueryVolumeInformationFile Hook,因为无法从堆栈中获取到参数
	//NtQueryVolumeInformationFile Hook 完美兼容win7以及win10 1803及以上版本
	setntqhookstats(FALSE);

	//设置NtDeviceIoControlFile Hook的Callback,win7,win10全系统兼容
	setdicprecabk(NtDeviceIoControlFileCallback);

	//设置NtQueryVolumeInformationFile Hook的Callback
	setntqcabk(NtQueryVolumeInformationFileCallback);
	return STATUS_SUCCESS;
}
