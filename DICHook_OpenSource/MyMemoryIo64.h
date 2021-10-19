#pragma once 

#ifndef __MyMempryIO64___Included___
#define __MyMempryIO64___Included___
#include "ntifs.h"
#include "windef.h"
#include "ntimage.h"
#include "intrin.h"
#include "DDKCommon.h"


struct HardwarePteX64 {
	union
	{
		ULONG64 all;
		struct {
			ULONG64 valid : 1;               //!< [0]
			ULONG64 write : 1;               //!< [1]
			ULONG64 owner : 1;               //!< [2]
			ULONG64 write_through : 1;       //!< [3]     PWT
			ULONG64 cache_disable : 1;       //!< [4]     PCD
			ULONG64 accessed : 1;            //!< [5]
			ULONG64 dirty : 1;               //!< [6]
			ULONG64 large_page : 1;          //!< [7]     PAT
			ULONG64 global : 1;              //!< [8]
			ULONG64 copy_on_write : 1;       //!< [9]
			ULONG64 prototype : 1;           //!< [10]
			ULONG64 reserved0 : 1;           //!< [11]
			ULONG64 page_frame_number : 36;  //!< [12:47]
			ULONG64 reserved1 : 4;           //!< [48:51]
			ULONG64 software_ws_index : 11;  //!< [52:62]
			ULONG64 no_execute : 1;          //!< [63]
		};
	};

};
struct CR4 {
	union {
		ULONG64 all;
		struct {
			ULONG64 VME : 1;
			ULONG64 PVI : 1;
			ULONG64 TSD : 1;
			ULONG64 DE : 1;
			ULONG64 PSE : 1;
			ULONG64 PAE : 1;
			ULONG64 MCE : 1;
			ULONG64 PGE : 1;
			ULONG64 PCE : 1;
			ULONG64 OSFXSR : 1;
			ULONG64 OSXMMEXCPT : 1;
			ULONG64 UMIP : 1;
			ULONG64 LA57 : 1;
			ULONG64 VMXE : 1;
			ULONG64 SMXE : 1;
			ULONG64 Reversed1 : 1;
			ULONG64 FSGSBASE : 1;
			ULONG64 PCIDE : 1;
			ULONG64 OSXSAVE : 1;
			ULONG64 Reversed2 : 1;
			ULONG64 SMEP : 1;
			ULONG64 SMAP : 1;
			ULONG64 PKE : 1;
		};
	};
};

typedef struct _MyVirtualAddress {
	union {
		struct {
			ULONG64 offset : 12;
			ULONG64 pte_index : 9;
			ULONG64 pde_index : 9;
			ULONG64 ppe_index : 9;
			ULONG64 pxe_index : 9;
		};
		ULONG64 VirtualAddress;
	};
}MyVirtualAddress, *PMyVirtualAddress;

typedef struct _MyPageTableEntry {
	union {
		struct {
			ULONG64 Present				 : 1;
			ULONG64 Writable			 : 1;
			ULONG64 UserAccessible		 : 1;
			ULONG64 WriteThrough		 : 1;
			ULONG64 DisableCache		 : 1;
			ULONG64 Accessd				 : 1;
			ULONG64 Dirty				 : 1;
			ULONG64 HugePage			 : 1;
			ULONG64 Global				 : 1;
			ULONG64 Available1			 : 3;
			ULONG64 PhysicalAddress		 : 40;
			ULONG64 Available2			 : 11;
			ULONG64 NoExecute			 : 1;
		};	
		ULONG64 Value;
	};
}MyPageTableEntry, *PMyPageTableEntry;

#define MmiInvaildAddressValue ((PVOID64)~0)

#define MmiEntryToAddress(v)			(((ULONG64)v)&0x000FFFFFFFFFF000)
#define MmiEntryFlag_Present			((ULONG64)0x0000000000000001)
#define MmiEntryFlag_Write				((ULONG64)0x0000000000000002)
#define MmiEntryFlag_UserAccessible		((ULONG64)0x0000000000000004)
#define MmiEntryFlag_WriteThrough		((ULONG64)0x0000000000000008)
#define MmiEntryFlag_DisableCache		((ULONG64)0x0000000000000010)
#define MmiEntryFlag_Accessed			((ULONG64)0x0000000000000020)
#define MmiEntryFlag_Dirty				((ULONG64)0x0000000000000040)
#define MmiEntryFlag_HugePage			((ULONG64)0x0000000000000080)
#define MmiEntryFlag_Global				((ULONG64)0x0000000000000100)
#define MmiEntryFlag_NoExecute			((ULONG64)0x8000000000000000)

#define MmiEntryFlag_EntryPage			(MmiEntryFlag_Present | MmiEntryFlag_Write | MmiEntryFlag_Accessed | MmiEntryFlag_Dirty)
#define MmiEntryFlag_ReadOnlyPage			(MmiEntryFlag_Present | MmiEntryFlag_Accessed | MmiEntryFlag_Dirty)

#define MmiCheckFlag(e,f) (e&f)

#define MmiMakeVirtualAddressHigh16(pxe) ((pxe&0x100)?((ULONG64)0xFFFF000000000000):((ULONG64)0x0000000000000000))
#define MmiMakeVirtualAddress_PXE(pxe) (MmiMakeVirtualAddressHigh16(pxe)|(((ULONG64)pxe)<<39))
#define MmiMakeVirtualAddress_PPE(pxe,ppe) (MmiMakeVirtualAddressHigh16(pxe)|(((ULONG64)pxe)<<39)|(((ULONG64)ppe)<<30))
#define MmiMakeVirtualAddress_PDE(pxe,ppe,pde) (MmiMakeVirtualAddressHigh16(pxe)|(((ULONG64)pxe)<<39)|(((ULONG64)ppe)<<30)|(((ULONG64)pde)<<21))
#define MmiMakeVirtualAddress_PTE(pxe,ppe,pde,pte) (MmiMakeVirtualAddressHigh16(pxe)|(((ULONG64)pxe)<<39)|(((ULONG64)ppe)<<30)|(((ULONG64)pde)<<21)|(((ULONG64)pte)<<12))
#define MmiMakeVirtualAddress(pxe,ppe,pde,pte,o) (MmiMakeVirtualAddressHigh16(pxe)|(((ULONG64)pxe)<<39)|(((ULONG64)ppe)<<30)|(((ULONG64)pde)<<21)|(((ULONG64)pte)<<12)|((ULONG64)o))


#define MmiVA_GetPXEIndex(v)	((((ULONG64)v)&((ULONG64)0x0000FF8000000000))>>39)
#define MmiVA_GetPPEIndex(v)	((((ULONG64)v)&((ULONG64)0x0000007FC0000000))>>30)
#define MmiVA_GetPDEIndex(v)	((((ULONG64)v)&((ULONG64)0x000000003FE00000))>>21)
#define MmiVA_GetPTEIndex(v)	((((ULONG64)v)&((ULONG64)0x00000000001FF000))>>12)
#define MmiVA_GetOFFSET(v)		(((ULONG64)v)&((ULONG64)0x0000000000000FFF))

#define MmiGetPhysicalPFN(p) (((ULONG64)(p)&0x0000FFFFFFFFF000)>>12)
#define MmiGetCr3() (MmiEntryToAddress(__readcr3()))

#ifdef __cplusplus 
extern "C" {
#endif

BOOLEAN Mmi_Init();
VOID MmiClearPteBase();
DWORD64 MmiGetPteAddress(PVOID64 Address);
DWORD64 MmiGetPdeAddress(PVOID64 Address);
DWORD64 MmiGetPpeAddress(PVOID64 Address);
DWORD64 MmiGetPxeAddress(PVOID64 Address);
VOID MmiFlushTLB(PVOID LinearAddress);
DWORD64 MmiGetPhysicalAddress(PVOID VirtualAddress);

ULONG64 MmiGetPhysicalAddress(PVOID va);
#ifdef __cplusplus 
}
#endif

#endif // !__MempryIO___Included___
