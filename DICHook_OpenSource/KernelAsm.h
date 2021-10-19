#pragma once

#ifndef _KernelAsm_INCLUDED_
#define _KernelAsm_INCLUDED_
#include "ntifs.h"

#undef KernelAsm_EXTERN
#define KernelAsm_EXTERN extern

#ifdef __cplusplus

#undef KernelAsm_EXTERN
#define KernelAsm_EXTERN extern "C"

#endif // __cplusplus

typedef struct _CpuidRet {
	ULONG EAX;
	ULONG EBX;
	ULONG ECX;
	ULONG EDX;
}CpuidRet;

typedef struct
{
	unsigned PE : 1;
	unsigned MP : 1;
	unsigned EM : 1;
	unsigned TS : 1;
	unsigned ET : 1;
	unsigned NE : 1;
	unsigned Reserved_1 : 10;
	unsigned WP : 1;
	unsigned Reserved_2 : 1;
	unsigned AM : 1;
	unsigned Reserved_3 : 10;
	unsigned NW : 1;
	unsigned CD : 1;
	unsigned PG : 1;
	unsigned Reserved_64 : 32;
}_CR0;

typedef struct
{
	unsigned VME : 1;
	unsigned PVI : 1;
	unsigned TSD : 1;
	unsigned DE : 1;
	unsigned PSE : 1;
	unsigned PAE : 1;
	unsigned MCE : 1;
	unsigned PGE : 1;
	unsigned PCE : 1;
	unsigned OSFXSR : 1;
	unsigned PSXMMEXCPT : 1;
	unsigned UNKONOWN_1 : 1;		//These are zero
	unsigned UNKONOWN_2 : 1;		//These are zero
	unsigned VMXE : 1;			//It's zero in normal
	unsigned Reserved : 18;		//These are zero
	unsigned Reserved_64 : 32;
}_CR4;

typedef struct
{
	unsigned CF : 1;
	unsigned Unknown_1 : 1;	//Always 1
	unsigned PF : 1;
	unsigned Unknown_2 : 1;	//Always 0
	unsigned AF : 1;
	unsigned Unknown_3 : 1;	//Always 0
	unsigned ZF : 1;
	unsigned SF : 1;
	unsigned TF : 1;
	unsigned IF : 1;
	unsigned DF : 1;
	unsigned OF : 1;
	unsigned TOPL : 2;
	unsigned NT : 1;
	unsigned Unknown_4 : 1;
	unsigned RF : 1;
	unsigned VM : 1;
	unsigned AC : 1;
	unsigned VIF : 1;
	unsigned VIP : 1;
	unsigned ID : 1;
	unsigned Reserved : 10;	//Always 0
	unsigned Reserved_64 : 32;	//Always 0
}_EFLAGS;

typedef struct
{
	unsigned SSE3 : 1;
	unsigned PCLMULQDQ : 1;
	unsigned DTES64 : 1;
	unsigned MONITOR : 1;
	unsigned DS_CPL : 1;
	unsigned VMX : 1;
	unsigned SMX : 1;
	unsigned EIST : 1;
	unsigned TM2 : 1;
	unsigned SSSE3 : 1;
	unsigned Reserved : 22;
	unsigned Reserved_64 : 32;
}_CPUID_ECX;

typedef struct _IA32_FEATURE_CONTROL_MSR
{
	unsigned Lock : 1;		// Bit 0 is the lock bit - cannot be modified once lock is set
	unsigned EnableVmxonSMX : 1;		// Undefined
	unsigned EnableVmxon : 1;		// Bit 2. If this bit is clear, VMXON causes a general protection exception
	unsigned Reserved2 : 29;	// Undefined
	unsigned Reserved3 : 32;	// Undefined

} IA32_FEATURE_CONTROL_MSR;

KernelAsm_EXTERN ULONG64 ReadSsQ(PULONG64);
KernelAsm_EXTERN VOID AsmInt2F();
KernelAsm_EXTERN VOID AsmIntE1();
KernelAsm_EXTERN ULONG64 AsmRdtsc();
KernelAsm_EXTERN ULONG64 AsmGetRFlags();
KernelAsm_EXTERN ULONG64 AsmGetRSP();
KernelAsm_EXTERN ULONG64 AsmReadCr0();
KernelAsm_EXTERN ULONG64 AsmReadCr2();
KernelAsm_EXTERN ULONG64 AsmReadCr3();
KernelAsm_EXTERN ULONG64 AsmReadCr4();
KernelAsm_EXTERN ULONG64 AsmReadCr8();
KernelAsm_EXTERN ULONG64 AsmReadMsr(ULONG Msr);
KernelAsm_EXTERN ULONG64 AsmWriteMsr(ULONG Msr, ULONG64 value);
KernelAsm_EXTERN ULONG64 AsmReadGs(ULONG offset);
KernelAsm_EXTERN VOID AsmWriteCr0(ULONG64 Cr0);
KernelAsm_EXTERN VOID AsmWriteCr4(ULONG64 Cr4);
KernelAsm_EXTERN VOID AsmWriteCr8(ULONG64 Cr8);
KernelAsm_EXTERN VOID AsmCpuid(ULONG Eax, ULONG Ecx, CpuidRet* ret);
KernelAsm_EXTERN ULONG64 AsmGetEs();
KernelAsm_EXTERN ULONG64 AsmGetCs();
KernelAsm_EXTERN ULONG64 AsmGetDs();
KernelAsm_EXTERN ULONG64 AsmGetFs();
KernelAsm_EXTERN ULONG64 AsmGetGs();
KernelAsm_EXTERN ULONG64 AsmGetSs();
KernelAsm_EXTERN ULONG64 AsmGetTr();
KernelAsm_EXTERN USHORT AsmGetLDTR();
KernelAsm_EXTERN ULONG64 AsmGetIdtBase();
KernelAsm_EXTERN UINT16 AsmGetIdtLimit();
KernelAsm_EXTERN ULONG64 AsmGetGdtBase();
KernelAsm_EXTERN UINT16 AsmGetGdtLimit();
KernelAsm_EXTERN ULONG64 AsmGetDr7();
KernelAsm_EXTERN ULONG64 AsmLoadAccessRightsByte(ULONG64 segment_selector);
typedef struct _INVPCID_CTX {
	ULONG64 PCID : 12;
	ULONG64 Reserved : 52;
	ULONG64 LinearAddress;
}INVPCID_CTX, * PINVPCID_CTX;
KernelAsm_EXTERN VOID AsmInvpcid(ULONG64 type, PINVPCID_CTX pDesc);
KernelAsm_EXTERN VOID AsmSti();
KernelAsm_EXTERN VOID AsmCli();

#define AsmGetCr0 AsmReadCr0
#define AsmGetCr3 AsmReadCr3
#define AsmGetCr4 AsmReadCr4
#define AsmGetCr8 AsmReadCr8

#define AsmReadES AsmGetEs
#define AsmReadCS AsmGetCs
#define AsmReadDS AsmGetDs
#define AsmReadFS AsmGetFs
#define AsmReadGS AsmGetGs
#define AsmReadSS AsmGetSs
#define AsmReadTR AsmGetTr
#define AsmReadLDTR AsmGetLDTR

#endif // !_KernelAsm_INCLUDED_

