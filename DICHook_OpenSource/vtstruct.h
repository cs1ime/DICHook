#pragma once


#ifndef _VTSTRUCT__INCLUDED__
#define _VTSTRUCT__INCLUDED__

#include "ntifs.h"

enum class Msr : unsigned long {
    kIa32ApicBase = 0x01B,

    kIa32FeatureControl = 0x03A,

    kIa32SysenterCs = 0x174,
    kIa32SysenterEsp = 0x175,
    kIa32SysenterEip = 0x176,

    kIa32Debugctl = 0x1D9,

    kIa32MtrrCap = 0xFE,
    kIa32MtrrDefType = 0x2FF,
    kIa32MtrrPhysBaseN = 0x200,
    kIa32MtrrPhysMaskN = 0x201,
    kIa32MtrrFix64k00000 = 0x250,
    kIa32MtrrFix16k80000 = 0x258,
    kIa32MtrrFix16kA0000 = 0x259,
    kIa32MtrrFix4kC0000 = 0x268,
    kIa32MtrrFix4kC8000 = 0x269,
    kIa32MtrrFix4kD0000 = 0x26A,
    kIa32MtrrFix4kD8000 = 0x26B,
    kIa32MtrrFix4kE0000 = 0x26C,
    kIa32MtrrFix4kE8000 = 0x26D,
    kIa32MtrrFix4kF0000 = 0x26E,
    kIa32MtrrFix4kF8000 = 0x26F,

    kIa32VmxBasic = 0x480,
    kIa32VmxPinbasedCtls = 0x481,
    kIa32VmxProcBasedCtls = 0x482,
    kIa32VmxExitCtls = 0x483,
    kIa32VmxEntryCtls = 0x484,
    kIa32VmxMisc = 0x485,
    kIa32VmxCr0Fixed0 = 0x486,
    kIa32VmxCr0Fixed1 = 0x487,
    kIa32VmxCr4Fixed0 = 0x488,
    kIa32VmxCr4Fixed1 = 0x489,
    kIa32VmxVmcsEnum = 0x48A,
    kIa32VmxProcBasedCtls2 = 0x48B,
    kIa32VmxEptVpidCap = 0x48C,
    kIa32VmxTruePinbasedCtls = 0x48D,
    kIa32VmxTrueProcBasedCtls = 0x48E,
    kIa32VmxTrueExitCtls = 0x48F,
    kIa32VmxTrueEntryCtls = 0x490,
    kIa32VmxVmfunc = 0x491,

    kIa32Efer = 0xC0000080,
    kIa32Star = 0xC0000081,
    kIa32Lstar = 0xC0000082,

    kIa32Fmask = 0xC0000084,

    kIa32FsBase = 0xC0000100,
    kIa32GsBase = 0xC0000101,
    kIa32KernelGsBase = 0xC0000102,
    kIa32TscAux = 0xC0000103,
};
enum class VmcsField : unsigned __int32 {
    // 16-Bit Control Field
    kVirtualProcessorId = 0x00000000,
    kPostedInterruptNotification = 0x00000002,
    kEptpIndex = 0x00000004,
    // 16-Bit Guest-State Fields
    kGuestEsSelector = 0x00000800,
    kGuestCsSelector = 0x00000802,
    kGuestSsSelector = 0x00000804,
    kGuestDsSelector = 0x00000806,
    kGuestFsSelector = 0x00000808,
    kGuestGsSelector = 0x0000080a,
    kGuestLdtrSelector = 0x0000080c,
    kGuestTrSelector = 0x0000080e,
    kGuestInterruptStatus = 0x00000810,
    kPmlIndex = 0x00000812,
    // 16-Bit Host-State Fields
    kHostEsSelector = 0x00000c00,
    kHostCsSelector = 0x00000c02,
    kHostSsSelector = 0x00000c04,
    kHostDsSelector = 0x00000c06,
    kHostFsSelector = 0x00000c08,
    kHostGsSelector = 0x00000c0a,
    kHostTrSelector = 0x00000c0c,
    // 64-Bit Control Fields
    kIoBitmapA = 0x00002000,
    kIoBitmapAHigh = 0x00002001,
    kIoBitmapB = 0x00002002,
    kIoBitmapBHigh = 0x00002003,
    kMsrBitmap = 0x00002004,
    kMsrBitmapHigh = 0x00002005,
    kVmExitMsrStoreAddr = 0x00002006,
    kVmExitMsrStoreAddrHigh = 0x00002007,
    kVmExitMsrLoadAddr = 0x00002008,
    kVmExitMsrLoadAddrHigh = 0x00002009,
    kVmEntryMsrLoadAddr = 0x0000200a,
    kVmEntryMsrLoadAddrHigh = 0x0000200b,
    kExecutiveVmcsPointer = 0x0000200c,
    kExecutiveVmcsPointerHigh = 0x0000200d,
    kTscOffset = 0x00002010,
    kTscOffsetHigh = 0x00002011,
    kVirtualApicPageAddr = 0x00002012,
    kVirtualApicPageAddrHigh = 0x00002013,
    kApicAccessAddr = 0x00002014,
    kApicAccessAddrHigh = 0x00002015,
    kEptPointer = 0x0000201a,
    kEptPointerHigh = 0x0000201b,
    kEoiExitBitmap0 = 0x0000201c,
    kEoiExitBitmap0High = 0x0000201d,
    kEoiExitBitmap1 = 0x0000201e,
    kEoiExitBitmap1High = 0x0000201f,
    kEoiExitBitmap2 = 0x00002020,
    kEoiExitBitmap2High = 0x00002021,
    kEoiExitBitmap3 = 0x00002022,
    kEoiExitBitmap3High = 0x00002023,
    kEptpListAddress = 0x00002024,
    kEptpListAddressHigh = 0x00002025,
    kVmreadBitmapAddress = 0x00002026,
    kVmreadBitmapAddressHigh = 0x00002027,
    kVmwriteBitmapAddress = 0x00002028,
    kVmwriteBitmapAddressHigh = 0x00002029,
    kVirtualizationExceptionInfoAddress = 0x0000202a,
    kVirtualizationExceptionInfoAddressHigh = 0x0000202b,
    kXssExitingBitmap = 0x0000202c,
    kXssExitingBitmapHigh = 0x0000202d,
    kEnclsExitingBitmap = 0x0000202e,
    kEnclsExitingBitmapHigh = 0x0000202f,
    kTscMultiplier = 0x00002032,
    kTscMultiplierHigh = 0x00002033,
    // 64-Bit Read-Only Data Field
    kGuestPhysicalAddress = 0x00002400,
    kGuestPhysicalAddressHigh = 0x00002401,
    // 64-Bit Guest-State Fields
    kVmcsLinkPointer = 0x00002800,
    kVmcsLinkPointerHigh = 0x00002801,
    kGuestIa32Debugctl = 0x00002802,
    kGuestIa32DebugctlHigh = 0x00002803,
    kGuestIa32Pat = 0x00002804,
    kGuestIa32PatHigh = 0x00002805,
    kGuestIa32Efer = 0x00002806,
    kGuestIa32EferHigh = 0x00002807,
    kGuestIa32PerfGlobalCtrl = 0x00002808,
    kGuestIa32PerfGlobalCtrlHigh = 0x00002809,
    kGuestPdptr0 = 0x0000280a,
    kGuestPdptr0High = 0x0000280b,
    kGuestPdptr1 = 0x0000280c,
    kGuestPdptr1High = 0x0000280d,
    kGuestPdptr2 = 0x0000280e,
    kGuestPdptr2High = 0x0000280f,
    kGuestPdptr3 = 0x00002810,
    kGuestPdptr3High = 0x00002811,
    kGuestIa32Bndcfgs = 0x00002812,
    kGuestIa32BndcfgsHigh = 0x00002813,
    // 64-Bit Host-State Fields
    kHostIa32Pat = 0x00002c00,
    kHostIa32PatHigh = 0x00002c01,
    kHostIa32Efer = 0x00002c02,
    kHostIa32EferHigh = 0x00002c03,
    kHostIa32PerfGlobalCtrl = 0x00002c04,
    kHostIa32PerfGlobalCtrlHigh = 0x00002c05,
    // 32-Bit Control Fields
    kPinBasedVmExecControl = 0x00004000,
    kCpuBasedVmExecControl = 0x00004002,
    kExceptionBitmap = 0x00004004,
    kPageFaultErrorCodeMask = 0x00004006,
    kPageFaultErrorCodeMatch = 0x00004008,
    kCr3TargetCount = 0x0000400a,
    kVmExitControls = 0x0000400c,
    kVmExitMsrStoreCount = 0x0000400e,
    kVmExitMsrLoadCount = 0x00004010,
    kVmEntryControls = 0x00004012,
    kVmEntryMsrLoadCount = 0x00004014,
    kVmEntryIntrInfoField = 0x00004016,
    kVmEntryExceptionErrorCode = 0x00004018,
    kVmEntryInstructionLen = 0x0000401a,
    kTprThreshold = 0x0000401c,
    kSecondaryVmExecControl = 0x0000401e,
    kPleGap = 0x00004020,
    kPleWindow = 0x00004022,
    // 32-Bit Read-Only Data Fields
    kVmInstructionError = 0x00004400,  // See: VM-Instruction Error Numbers
    kVmExitReason = 0x00004402,
    kVmExitIntrInfo = 0x00004404,
    kVmExitIntrErrorCode = 0x00004406,
    kIdtVectoringInfoField = 0x00004408,
    kIdtVectoringErrorCode = 0x0000440a,
    kVmExitInstructionLen = 0x0000440c,
    kVmxInstructionInfo = 0x0000440e,
    // 32-Bit Guest-State Fields
    kGuestEsLimit = 0x00004800,
    kGuestCsLimit = 0x00004802,
    kGuestSsLimit = 0x00004804,
    kGuestDsLimit = 0x00004806,
    kGuestFsLimit = 0x00004808,
    kGuestGsLimit = 0x0000480a,
    kGuestLdtrLimit = 0x0000480c,
    kGuestTrLimit = 0x0000480e,
    kGuestGdtrLimit = 0x00004810,
    kGuestIdtrLimit = 0x00004812,
    kGuestEsArBytes = 0x00004814,
    kGuestCsArBytes = 0x00004816,
    kGuestSsArBytes = 0x00004818,
    kGuestDsArBytes = 0x0000481a,
    kGuestFsArBytes = 0x0000481c,
    kGuestGsArBytes = 0x0000481e,
    kGuestLdtrArBytes = 0x00004820,
    kGuestTrArBytes = 0x00004822,
    kGuestInterruptibilityInfo = 0x00004824,
    kGuestActivityState = 0x00004826,
    kGuestSmbase = 0x00004828,
    kGuestSysenterCs = 0x0000482a,
    kVmxPreemptionTimerValue = 0x0000482e,
    // 32-Bit Host-State Field
    kHostIa32SysenterCs = 0x00004c00,
    // Natural-Width Control Fields
    kCr0GuestHostMask = 0x00006000,
    kCr4GuestHostMask = 0x00006002,
    kCr0ReadShadow = 0x00006004,
    kCr4ReadShadow = 0x00006006,
    kCr3TargetValue0 = 0x00006008,
    kCr3TargetValue1 = 0x0000600a,
    kCr3TargetValue2 = 0x0000600c,
    kCr3TargetValue3 = 0x0000600e,
    // Natural-Width Read-Only Data Fields
    kExitQualification = 0x00006400,
    kIoRcx = 0x00006402,
    kIoRsi = 0x00006404,
    kIoRdi = 0x00006406,
    kIoRip = 0x00006408,
    kGuestLinearAddress = 0x0000640a,
    // Natural-Width Guest-State Fields
    kGuestCr0 = 0x00006800,
    kGuestCr3 = 0x00006802,
    kGuestCr4 = 0x00006804,
    kGuestEsBase = 0x00006806,
    kGuestCsBase = 0x00006808,
    kGuestSsBase = 0x0000680a,
    kGuestDsBase = 0x0000680c,
    kGuestFsBase = 0x0000680e,
    kGuestGsBase = 0x00006810,
    kGuestLdtrBase = 0x00006812,
    kGuestTrBase = 0x00006814,
    kGuestGdtrBase = 0x00006816,
    kGuestIdtrBase = 0x00006818,
    kGuestDr7 = 0x0000681a,
    kGuestRsp = 0x0000681c,
    kGuestRip = 0x0000681e,
    kGuestRflags = 0x00006820,
    kGuestPendingDbgExceptions = 0x00006822,
    kGuestSysenterEsp = 0x00006824,
    kGuestSysenterEip = 0x00006826,
    // Natural-Width Host-State Fields
    kHostCr0 = 0x00006c00,
    kHostCr3 = 0x00006c02,
    kHostCr4 = 0x00006c04,
    kHostFsBase = 0x00006c06,
    kHostGsBase = 0x00006c08,
    kHostTrBase = 0x00006c0a,
    kHostGdtrBase = 0x00006c0c,
    kHostIdtrBase = 0x00006c0e,
    kHostIa32SysenterEsp = 0x00006c10,
    kHostIa32SysenterEip = 0x00006c12,
    kHostRsp = 0x00006c14,
    kHostRip = 0x00006c16
};
enum class InvVpidType : ULONG_PTR {
    kIndividualAddressInvalidation = 0,
    kSingleContextInvalidation = 1,
    kAllContextInvalidation = 2,
    kSingleContextInvalidationExceptGlobal = 3,
};
struct InvVpidDescriptor {
    USHORT vpid;
    USHORT reserved1;
    ULONG32 reserved2;
    ULONG64 linear_address;
};
enum class InvEptType : ULONG_PTR {
    kSingleContextInvalidation = 1,
    kGlobalInvalidation = 2,
};
union EptPointer {
    ULONG64 all;
    struct {
        ULONG64 memory_type : 3;                      //!< [0:2]
        ULONG64 page_walk_length : 3;                 //!< [3:5]
        ULONG64 enable_accessed_and_dirty_flags : 1;  //!< [6]
        ULONG64 reserved1 : 5;                        //!< [7:11]
        ULONG64 pml4_address : 36;                    //!< [12:48-1]
        ULONG64 reserved2 : 16;                       //!< [48:63]
    } fields;
};
struct InvEptDescriptor {
    EptPointer ept_pointer;
    ULONG64 reserved1;
};

union Ia32VmxBasicMsr {
    unsigned __int64 all;
    struct {
        unsigned revision_identifier : 31;    //!< [0:30]
        unsigned reserved1 : 1;               //!< [31]
        unsigned region_size : 12;            //!< [32:43]
        unsigned region_clear : 1;            //!< [44]
        unsigned reserved2 : 3;               //!< [45:47]
        unsigned supported_ia64 : 1;          //!< [48]
        unsigned supported_dual_moniter : 1;  //!< [49]
        unsigned memory_type : 4;             //!< [50:53]
        unsigned vm_exit_report : 1;          //!< [54]
        unsigned vmx_capability_hint : 1;     //!< [55]
        unsigned reserved3 : 8;               //!< [56:63]
    } fields;
};

union VmxVmEntryControls {
    unsigned int all;
    struct {
        unsigned reserved1 : 2;                          //!< [0:1]
        unsigned load_debug_controls : 1;                //!< [2]
        unsigned reserved2 : 6;                          //!< [3:8]
        unsigned ia32e_mode_guest : 1;                   //!< [9]
        unsigned entry_to_smm : 1;                       //!< [10]
        unsigned deactivate_dual_monitor_treatment : 1;  //!< [11]
        unsigned reserved3 : 1;                          //!< [12]
        unsigned load_ia32_perf_global_ctrl : 1;         //!< [13]
        unsigned load_ia32_pat : 1;                      //!< [14]
        unsigned load_ia32_efer : 1;                     //!< [15]
        unsigned load_ia32_bndcfgs : 1;                  //!< [16]
        unsigned conceal_vmentries_from_intel_pt : 1;    //!< [17]
    } fields;
};
union VmxVmExitControls {
    unsigned int all;
    struct {
        unsigned reserved1 : 2;                        //!< [0:1]
        unsigned save_debug_controls : 1;              //!< [2]
        unsigned reserved2 : 6;                        //!< [3:8]
        unsigned host_address_space_size : 1;          //!< [9]
        unsigned reserved3 : 2;                        //!< [10:11]
        unsigned load_ia32_perf_global_ctrl : 1;       //!< [12]
        unsigned reserved4 : 2;                        //!< [13:14]
        unsigned acknowledge_interrupt_on_exit : 1;    //!< [15]
        unsigned reserved5 : 2;                        //!< [16:17]
        unsigned save_ia32_pat : 1;                    //!< [18]
        unsigned load_ia32_pat : 1;                    //!< [19]
        unsigned save_ia32_efer : 1;                   //!< [20]
        unsigned load_ia32_efer : 1;                   //!< [21]
        unsigned save_vmx_preemption_timer_value : 1;  //!< [22]
        unsigned clear_ia32_bndcfgs : 1;               //!< [23]
        unsigned conceal_vmexits_from_intel_pt : 1;    //!< [24]
    } fields;
};

union VmxPinBasedControls {
    unsigned int all;
    struct {
        unsigned external_interrupt_exiting : 1;    //!< [0]
        unsigned reserved1 : 2;                     //!< [1:2]
        unsigned nmi_exiting : 1;                   //!< [3]
        unsigned reserved2 : 1;                     //!< [4]
        unsigned virtual_nmis : 1;                  //!< [5]
        unsigned activate_vmx_peemption_timer : 1;  //!< [6]
        unsigned process_posted_interrupts : 1;     //!< [7]
    } fields;
};
union VmxProcessorBasedControls {
    unsigned int all;
    struct {
        unsigned reserved1 : 2;                   //!< [0:1]
        unsigned interrupt_window_exiting : 1;    //!< [2]
        unsigned use_tsc_offseting : 1;           //!< [3]
        unsigned reserved2 : 3;                   //!< [4:6]
        unsigned hlt_exiting : 1;                 //!< [7]
        unsigned reserved3 : 1;                   //!< [8]
        unsigned invlpg_exiting : 1;              //!< [9]
        unsigned mwait_exiting : 1;               //!< [10]
        unsigned rdpmc_exiting : 1;               //!< [11]
        unsigned rdtsc_exiting : 1;               //!< [12]
        unsigned reserved4 : 2;                   //!< [13:14]
        unsigned cr3_load_exiting : 1;            //!< [15]
        unsigned cr3_store_exiting : 1;           //!< [16]
        unsigned reserved5 : 2;                   //!< [17:18]
        unsigned cr8_load_exiting : 1;            //!< [19]
        unsigned cr8_store_exiting : 1;           //!< [20]
        unsigned use_tpr_shadow : 1;              //!< [21]
        unsigned nmi_window_exiting : 1;          //!< [22]
        unsigned mov_dr_exiting : 1;              //!< [23]
        unsigned unconditional_io_exiting : 1;    //!< [24]
        unsigned use_io_bitmaps : 1;              //!< [25]
        unsigned reserved6 : 1;                   //!< [26]
        unsigned monitor_trap_flag : 1;           //!< [27]
        unsigned use_msr_bitmaps : 1;             //!< [28]
        unsigned monitor_exiting : 1;             //!< [29]
        unsigned pause_exiting : 1;               //!< [30]
        unsigned activate_secondary_control : 1;  //!< [31]
    } fields;
};
/// See: Definitions of Secondary Processor-Based VM-Execution Controls
union VmxSecondaryProcessorBasedControls {
    unsigned int all;
    struct {
        unsigned virtualize_apic_accesses : 1;            //!< [0]
        unsigned enable_ept : 1;                          //!< [1]
        unsigned descriptor_table_exiting : 1;            //!< [2]
        unsigned enable_rdtscp : 1;                       //!< [3]
        unsigned virtualize_x2apic_mode : 1;              //!< [4]
        unsigned enable_vpid : 1;                         //!< [5]
        unsigned wbinvd_exiting : 1;                      //!< [6]
        unsigned unrestricted_guest : 1;                  //!< [7]
        unsigned apic_register_virtualization : 1;        //!< [8]
        unsigned virtual_interrupt_delivery : 1;          //!< [9]
        unsigned pause_loop_exiting : 1;                  //!< [10]
        unsigned rdrand_exiting : 1;                      //!< [11]
        unsigned enable_invpcid : 1;                      //!< [12]
        unsigned enable_vm_functions : 1;                 //!< [13]
        unsigned vmcs_shadowing : 1;                      //!< [14]
        unsigned reserved1 : 1;                           //!< [15]
        unsigned rdseed_exiting : 1;                      //!< [16]
        unsigned reserved2 : 1;                           //!< [17]
        unsigned ept_violation_ve : 1;                    //!< [18]
        unsigned reserved3 : 1;                           //!< [19]
        unsigned enable_xsaves_xstors : 1;                //!< [20]
        unsigned reserved4 : 1;                           //!< [21]
        unsigned mode_based_execute_control_for_ept : 1;  //!< [22]
        unsigned reserved5 : 2;                           //!< [23:24]
        unsigned use_tsc_scaling : 1;                     //!< [25]
    } fields;
};
/// See: Guest Register State
union VmxRegmentDescriptorAccessRight {
    unsigned int all;
    struct {
        unsigned type : 4;        //!< [0:3]
        unsigned system : 1;      //!< [4]
        unsigned dpl : 2;         //!< [5:6]
        unsigned present : 1;     //!< [7]
        unsigned reserved1 : 4;   //!< [8:11]
        unsigned avl : 1;         //!< [12]
        unsigned l : 1;           //!< [13] Reserved (except for CS) 64-bit mode
        unsigned db : 1;          //!< [14]
        unsigned gran : 1;        //!< [15]
        unsigned unusable : 1;    //!< [16] Segment unusable
        unsigned reserved2 : 15;  //!< [17:31]
    } fields;
};

union Cr0 {
    ULONG_PTR all;
    struct {
        unsigned pe : 1;          //!< [0] Protected Mode Enabled
        unsigned mp : 1;          //!< [1] Monitor Coprocessor FLAG
        unsigned em : 1;          //!< [2] Emulate FLAG
        unsigned ts : 1;          //!< [3] Task Switched FLAG
        unsigned et : 1;          //!< [4] Extension Type FLAG
        unsigned ne : 1;          //!< [5] Numeric Error
        unsigned reserved1 : 10;  //!< [6:15]
        unsigned wp : 1;          //!< [16] Write Protect
        unsigned reserved2 : 1;   //!< [17]
        unsigned am : 1;          //!< [18] Alignment Mask
        unsigned reserved3 : 10;  //!< [19:28]
        unsigned nw : 1;          //!< [29] Not Write-Through
        unsigned cd : 1;          //!< [30] Cache Disable
        unsigned pg : 1;          //!< [31] Paging Enabled
    } fields;
};
static_assert(sizeof(Cr0) == sizeof(void*), "Size check");

/// See: CONTROL REGISTERS
union Cr4 {
    ULONG_PTR all;
    struct {
        unsigned vme : 1;         //!< [0] Virtual Mode Extensions
        unsigned pvi : 1;         //!< [1] Protected-Mode Virtual Interrupts
        unsigned tsd : 1;         //!< [2] Time Stamp Disable
        unsigned de : 1;          //!< [3] Debugging Extensions
        unsigned pse : 1;         //!< [4] Page Size Extensions
        unsigned pae : 1;         //!< [5] Physical Address Extension
        unsigned mce : 1;         //!< [6] Machine-Check Enable
        unsigned pge : 1;         //!< [7] Page Global Enable
        unsigned pce : 1;         //!< [8] Performance-Monitoring Counter Enable
        unsigned osfxsr : 1;      //!< [9] OS Support for FXSAVE/FXRSTOR
        unsigned osxmmexcpt : 1;  //!< [10] OS Support for Unmasked SIMD Exceptions
        unsigned reserved1 : 2;   //!< [11:12]
        unsigned vmxe : 1;        //!< [13] Virtual Machine Extensions Enabled
        unsigned smxe : 1;        //!< [14] SMX-Enable Bit
        unsigned reserved2 : 2;   //!< [15:16]
        unsigned pcide : 1;       //!< [17] PCID Enable
        unsigned osxsave : 1;  //!< [18] XSAVE and Processor Extended States-Enable
        unsigned reserved3 : 1;  //!< [19]
        unsigned smep : 1;  //!< [20] Supervisor Mode Execution Protection Enable
        unsigned smap : 1;  //!< [21] Supervisor Mode Access Protection Enable
    } fields;
};
static_assert(sizeof(Cr4) == sizeof(void*), "Size check");

/// Represents a stack layout after PUSHAQ
union GpRegistersX64 {
    ULONG_PTR all[16];
    struct {
        ULONG_PTR r15;
        ULONG_PTR r14;
        ULONG_PTR r13;
        ULONG_PTR r12;
        ULONG_PTR r11;
        ULONG_PTR r10;
        ULONG_PTR r9;
        ULONG_PTR r8;
        ULONG_PTR di;
        ULONG_PTR si;
        ULONG_PTR bp;
        ULONG_PTR sp;
        ULONG_PTR bx;
        ULONG_PTR dx;
        ULONG_PTR cx;
        ULONG_PTR ax;
    };
};

/// Represents a stack layout after PUSHAD
struct GpRegistersX86 {
    ULONG_PTR di;
    ULONG_PTR si;
    ULONG_PTR bp;
    ULONG_PTR sp;
    ULONG_PTR bx;
    ULONG_PTR dx;
    ULONG_PTR cx;
    ULONG_PTR ax;
};

/// Represents a stack layout after PUSHAx
#if defined(_AMD64_)
using GpRegisters = GpRegistersX64;
#else
using GpRegisters = GpRegistersX86;
#endif
struct KtrapFrameX86 {
    ULONG reserved1[26];
    ULONG ip;  //!< Called EIP in _KTRAP_FRAME
    ULONG reserved2[2];
    ULONG sp;  //!< Called HardwareEsp in _KTRAP_FRAME
    ULONG reserved3[5];
};
static_assert(sizeof(KtrapFrameX86) == 0x8c, "structure size mismatch");
#if !defined(__clang__)
static_assert(FIELD_OFFSET(KtrapFrameX86, ip) == 0x68, "structure size mismatch");
static_assert(FIELD_OFFSET(KtrapFrameX86, sp) == 0x74, "structure size mismatch");
#endif

/// nt!_KTRAP_FRAME on x64
struct KtrapFrameX64 {
    ULONG64 reserved1[45];
    ULONG64 ip;  //!< Called EIP in _KTRAP_FRAME
    ULONG64 reserved2[2];
    ULONG64 sp;  //!< Called Rsp in _KTRAP_FRAME
    ULONG64 reserved3;
};
static_assert(sizeof(KtrapFrameX64) == 0x190, "structure size mismatch");
#if !defined(__clang__)
static_assert(FIELD_OFFSET(KtrapFrameX64, ip) == 0x168, "structure size mismatch");
static_assert(FIELD_OFFSET(KtrapFrameX64, sp) == 0x180, "structure size mismatch");
#endif

/// See: Stack Usage on Transfers to Interrupt and Exception-Handling Routines
struct MachineFrame {
    ULONG_PTR ip;
    ULONG_PTR cs;
    ULONG_PTR flags;
    ULONG_PTR sp;
    ULONG_PTR ss;
};

#if defined(_AMD64_)
using KtrapFrame = KtrapFrameX64;
#else
using KtrapFrame = KtrapFrameX86;
#endif
struct VmmInitialStack {
    GpRegisters gp_regs;
    KtrapFrame trap_frame;
    //ProcessorData* processor_data;
};
union MovCrQualification {
    ULONG_PTR all;
    struct {
        ULONG_PTR control_register : 4;   //!< [0:3]
        ULONG_PTR access_type : 2;        //!< [4:5]
        ULONG_PTR lmsw_operand_type : 1;  //!< [6]
        ULONG_PTR reserved1 : 1;          //!< [7]
        ULONG_PTR gp_register : 4;        //!< [8:11]
        ULONG_PTR reserved2 : 4;          //!< [12:15]
        ULONG_PTR lmsw_source_data : 16;  //!< [16:31]
        ULONG_PTR reserved3 : 32;         //!< [32:63]
    } fields;
};

#endif // !_VTSTRUCT__INCLUDED__

/// See: BASIC VMX INFORMATION

