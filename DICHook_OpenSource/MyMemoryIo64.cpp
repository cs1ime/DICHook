#include "MyMemoryIo64.h"

DWORD64 g_PteBase = NULL;
DWORD64 g_PdeBase = NULL;
DWORD64 g_PpeBase = NULL;
DWORD64 g_PxeBase = NULL;

union VirtualAddress {
	ULONG64 all;
	struct {
		ULONG64 offset : 12;
		ULONG64 pte_index : 9;
		ULONG64 pde_index : 9;
		ULONG64 ppe_index : 9;
		ULONG64 pxe_index : 9;
		ULONG64 head : 16;
	};
};

DWORD64 MmiGetPteAddress(PVOID64 Address) {
	return ((((((DWORD64)Address) & 0x0000FFFFFFFFF000) >> 12) << 3) + g_PteBase);
}
DWORD64 MmiGetPdeAddress(PVOID64 Address) {
	return ((((((DWORD64)Address) & 0x0000FFFFFFFFF000) >> 21) << 3) + g_PdeBase);
}
DWORD64 MmiGetPpeAddress(PVOID64 Address) {
	return ((((((DWORD64)Address) & 0x0000FFFFFFFFF000) >> 30) << 3) + g_PpeBase);
}
DWORD64 MmiGetPxeAddress(PVOID64 Address) {
	return ((((((DWORD64)Address) & 0x0000FFFFFFFFF000) >> 39) << 3) + g_PxeBase);
}

bool g_invpcid_enable = 0;
bool g_clfsh_enable = 0;
BOOLEAN Mmi_Init() {
	if (g_PteBase)
		return TRUE;
	g_PteBase = (DWORD64)KGetPteBase();
	if (g_PteBase == 0) {
		KeBugCheck(0x8787878);
		return FALSE;
	}
	g_PdeBase = MmiGetPteAddress((PVOID)g_PteBase);
	g_PpeBase = MmiGetPteAddress((PVOID)g_PdeBase);
	g_PxeBase = MmiGetPteAddress((PVOID)g_PpeBase);

	CpuidRet cpuid_ret;
	memset(&cpuid_ret, 0, sizeof(cpuid_ret));
	AsmCpuid(7, 0, &cpuid_ret);
	g_invpcid_enable = cpuid_ret.EBX & 0x400;
	AsmCpuid(1, 0, &cpuid_ret);
	g_clfsh_enable = cpuid_ret.EDX & 0x80000;
	return TRUE;
}
VOID MmiClearPteBase() {
	g_PteBase = 0;
	g_PdeBase = 0;
	g_PpeBase = 0;
	g_PxeBase = 0;
}
VOID MmiFlushTLB(PVOID LinearAddress) {
	/*if (g_invpcid_enable) {
		BOOL i_enable = AsmGetRFlags() & 0x200;
		if (i_enable)
			_disable();
		CR4 cr4;
		cr4.all = __readcr4();
		if (cr4.PCIDE) {
			INVPCID_CTX ctx;
			ctx.LinearAddress = (ULONG64)LinearAddress;
			ctx.PCID = __readcr3() & 0xFFF;
			if (ctx.PCID != 0) {
				AsmInvpcid(0, &ctx);
				return;
			}
		}
		if (i_enable)
			_enable();

	}*/
	/*if (g_clfsh_enable) {
		_mm_mfence();
		_mm_clflush(LinearAddress);
	}
	else*/
	__invlpg(LinearAddress);

}
ULONG64 MmiGetPhysicalAddress(PVOID va) {
	HardwarePteX64 PageEntry[3] = { 0 };
	HardwarePteX64 page;

	PULONG64 p_pxe = (PULONG64)MmiGetPxeAddress(va);
	page.all = *p_pxe;
	if (page.valid == 0)
		return 0;
	if (page.large_page) {
		ULONG64 off = (ULONG64)va & 0x7FFFFFFFFF;
		ULONG64 PhyAdd = page.page_frame_number << 12;
		PhyAdd += off;
		return PhyAdd;
	}
	PULONG64 p_ppe = (PULONG64)MmiGetPpeAddress(va);
	page.all = *p_ppe;
	if (page.valid == 0)
		return 0;
	if (page.large_page) {
		ULONG64 off = (ULONG64)va & 0x3FFFFFFF;
		ULONG64 PhyAdd = page.page_frame_number << 12;
		PhyAdd += off;
		return PhyAdd;
	}
	PULONG64 p_pde = (PULONG64)MmiGetPdeAddress(va);
	page.all = *p_pde;
	if (page.valid == 0)
		return 0;
	if (page.large_page) {
		ULONG64 off = (ULONG64)va & 0x1FFFFF;
		ULONG64 PhyAdd = page.page_frame_number << 12;
		PhyAdd += off;
		return PhyAdd;
	}
	PULONG64 p_pte = (PULONG64)MmiGetPteAddress(va);
	page.all = *p_pte;
	if (page.valid == 0)
		return 0;
	ULONG64 off = (ULONG64)va & 0xFFF;
	ULONG64 PhyAdd = page.page_frame_number << 12;
	PhyAdd += off;
	return PhyAdd;
}
