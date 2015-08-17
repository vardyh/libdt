/*
 * i386 virtual CPU header
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef CPU_I386_H
#define CPU_I386_H

#include <setjmp.h>

#include "osdep.h"
#include "qemu-queue.h"
#include "qemu-common.h"

#pragma pack (push, 1)

typedef uint64_t target_phys_addr_t;

#ifdef __x86_64__
# define HOST_LONG_BITS 64
#else
# define HOST_LONG_BITS 32
#endif

#include "vxeng.h"

#define CPUState struct CPUX86State

#if TARGET_LONG_BITS == 32
#define TARGET_FMT_lx "%08x"
#define TARGET_FMT_ld "%d"
#define TARGET_FMT_lu "%u"
#elif TARGET_LONG_BITS == 64
#define TARGET_FMT_lx "%016" LL"x"
#define TARGET_FMT_ld "%" LL"d"
#define TARGET_FMT_lu "%" LL"u"
#endif

#define EXCP_INTERRUPT 	0x10000 /* async interruption */
#define EXCP_HLT        0x10001 /* hlt instruction reached */
#define EXCP_DEBUG      0x10002 /* cpu stopped after a breakpoint or singlestep */
#define EXCP_HALTED     0x10003 /* cpu is halted (waiting for external event) */

#define TB_JMP_CACHE_BITS 12
#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)

/* Only the bottom TB_JMP_PAGE_BITS of the jump cache hash bits vary for
   addresses on the same page.  The top bits are the same.  This allows
   TLB invalidation to quickly clear a subset of the hash table.  */
#define TB_JMP_PAGE_BITS (TB_JMP_CACHE_BITS / 2)
#define TB_JMP_PAGE_SIZE (1 << TB_JMP_PAGE_BITS)
#define TB_JMP_ADDR_MASK (TB_JMP_PAGE_SIZE - 1)
#define TB_JMP_PAGE_MASK (TB_JMP_CACHE_SIZE - TB_JMP_PAGE_SIZE)

#define CPU_TLB_BITS 8
#define CPU_TLB_SIZE (1 << CPU_TLB_BITS)

#if HOST_LONG_BITS == 32 && TARGET_LONG_BITS == 32
#define CPU_TLB_ENTRY_BITS 4
#else
#define CPU_TLB_ENTRY_BITS 5
#endif

typedef struct CPUTLBEntry {
	/* bit TARGET_LONG_BITS to TARGET_PAGE_BITS : virtual address
	   bit TARGET_PAGE_BITS-1..4  : Nonzero for accesses that should not
	   go directly to ram.
	   bit 3                      : indicates that the entry is invalid
	   bit 2..0                   : zero
	*/
	target_ulong addr_read;
	target_ulong addr_write;
	target_ulong addr_code;
	/* Addend to virtual address to get host address.  IO accesses
	   use the corresponding iotlb value.  */
	unsigned long addend;
} CPUTLBEntry;

typedef struct icount_decr_u16 {
	uint16_t low;
	uint16_t high;
} icount_decr_u16;

typedef struct CPUBreakpoint {
	target_ulong pc;
	int flags; /* BP_* */
	QTAILQ_ENTRY(CPUBreakpoint) entry;
} CPUBreakpoint;

typedef struct CPUWatchpoint {
	target_ulong vaddr;
	target_ulong len_mask;
	int flags; /* BP_* */
	QTAILQ_ENTRY(CPUWatchpoint) entry;
} CPUWatchpoint;

#define CPU_TEMP_BUF_NLONGS 128

#include "softfloat.h"

/* segment descriptor fields */
#define DESC_G_MASK     (1 << 23)
#define DESC_B_SHIFT    22
#define DESC_B_MASK     (1 << DESC_B_SHIFT)
#define DESC_L_SHIFT    21 /* x86_64 only : 64 bit code segment */
#define DESC_L_MASK     (1 << DESC_L_SHIFT)
#define DESC_AVL_MASK   (1 << 20)
#define DESC_P_MASK     (1 << 15)
#define DESC_DPL_SHIFT  13
#define DESC_DPL_MASK   (3 << DESC_DPL_SHIFT)
#define DESC_S_MASK     (1 << 12)
#define DESC_TYPE_SHIFT 8
#define DESC_TYPE_MASK  (15 << DESC_TYPE_SHIFT)
#define DESC_A_MASK     (1 << 8)

#define DESC_CS_MASK    (1 << 11) /* 1=code segment 0=data segment */
#define DESC_C_MASK     (1 << 10) /* code: conforming */
#define DESC_R_MASK     (1 << 9)  /* code: readable */

#define DESC_E_MASK     (1 << 10) /* data: expansion direction */
#define DESC_W_MASK     (1 << 9)  /* data: writable */

#define DESC_TSS_BUSY_MASK (1 << 9)

/* hidden flags - used internally by qemu to represent additional cpu
   states. Only the CPL, INHIBIT_IRQ, SMM and SVMI are not
   redundant. We avoid using the IOPL_MASK, TF_MASK and VM_MASK bit
   position to ease oring with eflags. */
/* current cpl */
#define HF_CPL_SHIFT         0
/* true if soft mmu is being used */
#define HF_SOFTMMU_SHIFT     2
/* true if hardware interrupts must be disabled for next instruction */
#define HF_INHIBIT_IRQ_SHIFT 3
/* 16 or 32 segments */
#define HF_CS32_SHIFT        4
#define HF_SS32_SHIFT        5
/* zero base for DS, ES and SS : can be '0' only in 32 bit CS segment */
#define HF_ADDSEG_SHIFT      6
/* copy of CR0.PE (protected mode) */
#define HF_PE_SHIFT          7
#define HF_TF_SHIFT          8 /* must be same as eflags */
#define HF_MP_SHIFT          9 /* the order must be MP, EM, TS */
#define HF_EM_SHIFT         10
#define HF_TS_SHIFT         11
#define HF_IOPL_SHIFT       12 /* must be same as eflags */
#define HF_LMA_SHIFT        14 /* only used on x86_64: long mode active */
#define HF_CS64_SHIFT       15 /* only used on x86_64: 64 bit code segment  */
#define HF_RF_SHIFT         16 /* must be same as eflags */
#define HF_VM_SHIFT         17 /* must be same as eflags */
#define HF_SMM_SHIFT        19 /* CPU in SMM mode */
#define HF_SVME_SHIFT       20 /* SVME enabled (copy of EFER.SVME) */
#define HF_SVMI_SHIFT       21 /* SVM intercepts are active */
#define HF_OSFXSR_SHIFT     22 /* CR4.OSFXSR */

#define HF_CPL_MASK          (3 << HF_CPL_SHIFT)
#define HF_SOFTMMU_MASK      (1 << HF_SOFTMMU_SHIFT)
#define HF_INHIBIT_IRQ_MASK  (1 << HF_INHIBIT_IRQ_SHIFT)
#define HF_CS32_MASK         (1 << HF_CS32_SHIFT)
#define HF_SS32_MASK         (1 << HF_SS32_SHIFT)
#define HF_ADDSEG_MASK       (1 << HF_ADDSEG_SHIFT)
#define HF_PE_MASK           (1 << HF_PE_SHIFT)
#define HF_TF_MASK           (1 << HF_TF_SHIFT)
#define HF_MP_MASK           (1 << HF_MP_SHIFT)
#define HF_EM_MASK           (1 << HF_EM_SHIFT)
#define HF_TS_MASK           (1 << HF_TS_SHIFT)
#define HF_IOPL_MASK         (3 << HF_IOPL_SHIFT)
#define HF_LMA_MASK          (1 << HF_LMA_SHIFT)
#define HF_CS64_MASK         (1 << HF_CS64_SHIFT)
#define HF_RF_MASK           (1 << HF_RF_SHIFT)
#define HF_VM_MASK           (1 << HF_VM_SHIFT)
#define HF_SMM_MASK          (1 << HF_SMM_SHIFT)
#define HF_SVME_MASK         (1 << HF_SVME_SHIFT)
#define HF_SVMI_MASK         (1 << HF_SVMI_SHIFT)
#define HF_OSFXSR_MASK       (1 << HF_OSFXSR_SHIFT)

/* hflags2 */

#define HF2_GIF_SHIFT        0 /* if set CPU takes interrupts */
#define HF2_HIF_SHIFT        1 /* value of IF_MASK when entering SVM */
#define HF2_NMI_SHIFT        2 /* CPU serving NMI */
#define HF2_VINTR_SHIFT      3 /* value of V_INTR_MASKING bit */

#define HF2_GIF_MASK          (1 << HF2_GIF_SHIFT)
#define HF2_HIF_MASK          (1 << HF2_HIF_SHIFT)
#define HF2_NMI_MASK          (1 << HF2_NMI_SHIFT)
#define HF2_VINTR_MASK        (1 << HF2_VINTR_SHIFT)

#define PG_PRESENT_BIT	0
#define PG_RW_BIT	1
#define PG_USER_BIT	2
#define PG_PWT_BIT	3
#define PG_PCD_BIT	4
#define PG_ACCESSED_BIT	5
#define PG_DIRTY_BIT	6
#define PG_PSE_BIT	7
#define PG_GLOBAL_BIT	8
#define PG_NX_BIT	63

#define PG_PRESENT_MASK  (1 << PG_PRESENT_BIT)
#define PG_RW_MASK	 (1 << PG_RW_BIT)
#define PG_USER_MASK	 (1 << PG_USER_BIT)
#define PG_PWT_MASK	 (1 << PG_PWT_BIT)
#define PG_PCD_MASK	 (1 << PG_PCD_BIT)
#define PG_ACCESSED_MASK (1 << PG_ACCESSED_BIT)
#define PG_DIRTY_MASK	 (1 << PG_DIRTY_BIT)
#define PG_PSE_MASK	 (1 << PG_PSE_BIT)
#define PG_GLOBAL_MASK	 (1 << PG_GLOBAL_BIT)
#define PG_NX_MASK	 (1LL << PG_NX_BIT)

#define PG_ERROR_W_BIT     1

#define PG_ERROR_P_MASK    0x01
#define PG_ERROR_W_MASK    (1 << PG_ERROR_W_BIT)
#define PG_ERROR_U_MASK    0x04
#define PG_ERROR_RSVD_MASK 0x08
#define PG_ERROR_I_D_MASK  0x10

#define MCG_CTL_P	(1ULL<<8)   /* MCG_CAP register available */
#define MCG_SER_P	(1ULL<<24) /* MCA recovery/new status bits */

#define MCE_CAP_DEF	(MCG_CTL_P|MCG_SER_P)
#define MCE_BANKS_DEF	10

#define MCG_STATUS_RIPV	(1ULL<<0)   /* restart ip valid */
#define MCG_STATUS_EIPV	(1ULL<<1)   /* ip points to correct instruction */
#define MCG_STATUS_MCIP	(1ULL<<2)   /* machine check in progress */

#define MCI_STATUS_VAL	(1ULL<<63)  /* valid error */
#define MCI_STATUS_OVER	(1ULL<<62)  /* previous errors lost */
#define MCI_STATUS_UC	(1ULL<<61)  /* uncorrected error */
#define MCI_STATUS_EN	(1ULL<<60)  /* error enabled */
#define MCI_STATUS_MISCV (1ULL<<59) /* misc error reg. valid */
#define MCI_STATUS_ADDRV (1ULL<<58) /* addr reg. valid */
#define MCI_STATUS_PCC	(1ULL<<57)  /* processor context corrupt */
#define MCI_STATUS_S	(1ULL<<56)  /* Signaled machine check */
#define MCI_STATUS_AR	(1ULL<<55)  /* Action required */

  /* MISC register defines */
#define MCM_ADDR_SEGOFF	0	/* segment offset */
#define MCM_ADDR_LINEAR	1	/* linear address */
#define MCM_ADDR_PHYS	2	/* physical address */
#define MCM_ADDR_MEM	3	/* memory address */
#define MCM_ADDR_GENERIC 7	/* generic */

#define MSR_IA32_TSC                    0x10
#define MSR_IA32_APICBASE               0x1b
#define MSR_IA32_APICBASE_BSP           (1<<8)
#define MSR_IA32_APICBASE_ENABLE        (1<<11)
#define MSR_IA32_APICBASE_BASE          (0xfffff<<12)

#define MSR_MTRRcap			0xfe
#define MSR_MTRRcap_VCNT		8
#define MSR_MTRRcap_FIXRANGE_SUPPORT	(1 << 8)
#define MSR_MTRRcap_WC_SUPPORTED	(1 << 10)

#define MSR_IA32_SYSENTER_CS            0x174
#define MSR_IA32_SYSENTER_ESP           0x175
#define MSR_IA32_SYSENTER_EIP           0x176

#define MSR_MCG_CAP                     0x179
#define MSR_MCG_STATUS                  0x17a
#define MSR_MCG_CTL                     0x17b

#define MSR_IA32_PERF_STATUS            0x198

#define MSR_MTRRphysBase(reg)		(0x200 + 2 * (reg))
#define MSR_MTRRphysMask(reg)		(0x200 + 2 * (reg) + 1)

#define MSR_MTRRfix64K_00000		0x250
#define MSR_MTRRfix16K_80000		0x258
#define MSR_MTRRfix16K_A0000		0x259
#define MSR_MTRRfix4K_C0000		0x268
#define MSR_MTRRfix4K_C8000		0x269
#define MSR_MTRRfix4K_D0000		0x26a
#define MSR_MTRRfix4K_D8000		0x26b
#define MSR_MTRRfix4K_E0000		0x26c
#define MSR_MTRRfix4K_E8000		0x26d
#define MSR_MTRRfix4K_F0000		0x26e
#define MSR_MTRRfix4K_F8000		0x26f

#define MSR_PAT                         0x277

#define MSR_MTRRdefType			0x2ff

#define MSR_MC0_CTL			0x400
#define MSR_MC0_STATUS			0x401
#define MSR_MC0_ADDR			0x402
#define MSR_MC0_MISC			0x403

#define MSR_EFER                        0xc0000080

#define MSR_EFER_SCE   (1 << 0)
#define MSR_EFER_LME   (1 << 8)
#define MSR_EFER_LMA   (1 << 10)
#define MSR_EFER_NXE   (1 << 11)
#define MSR_EFER_SVME  (1 << 12)
#define MSR_EFER_FFXSR (1 << 14)

#define MSR_STAR                        0xc0000081
#define MSR_LSTAR                       0xc0000082
#define MSR_CSTAR                       0xc0000083
#define MSR_FMASK                       0xc0000084
#define MSR_FSBASE                      0xc0000100
#define MSR_GSBASE                      0xc0000101
#define MSR_KERNELGSBASE                0xc0000102
#define MSR_TSC_AUX                     0xc0000103

#define MSR_VM_HSAVE_PA                 0xc0010117

/* cpuid_features bits */
#define CPUID_FP87 (1 << 0)
#define CPUID_VME  (1 << 1)
#define CPUID_DE   (1 << 2)
#define CPUID_PSE  (1 << 3)
#define CPUID_TSC  (1 << 4)
#define CPUID_MSR  (1 << 5)
#define CPUID_PAE  (1 << 6)
#define CPUID_MCE  (1 << 7)
#define CPUID_CX8  (1 << 8)
#define CPUID_APIC (1 << 9)
#define CPUID_SEP  (1 << 11) /* sysenter/sysexit */
#define CPUID_MTRR (1 << 12)
#define CPUID_PGE  (1 << 13)
#define CPUID_MCA  (1 << 14)
#define CPUID_CMOV (1 << 15)
#define CPUID_PAT  (1 << 16)
#define CPUID_PSE36   (1 << 17)
#define CPUID_PN   (1 << 18)
#define CPUID_CLFLUSH (1 << 19)
#define CPUID_DTS (1 << 21)
#define CPUID_ACPI (1 << 22)
#define CPUID_MMX  (1 << 23)
#define CPUID_FXSR (1 << 24)
#define CPUID_SSE  (1 << 25)
#define CPUID_SSE2 (1 << 26)
#define CPUID_SS (1 << 27)
#define CPUID_HT (1 << 28)
#define CPUID_TM (1 << 29)
#define CPUID_IA64 (1 << 30)
#define CPUID_PBE (1 << 31)

#define CPUID_EXT_SSE3     (1 << 0)
#define CPUID_EXT_DTES64   (1 << 2)
#define CPUID_EXT_MONITOR  (1 << 3)
#define CPUID_EXT_DSCPL    (1 << 4)
#define CPUID_EXT_VMX      (1 << 5)
#define CPUID_EXT_SMX      (1 << 6)
#define CPUID_EXT_EST      (1 << 7)
#define CPUID_EXT_TM2      (1 << 8)
#define CPUID_EXT_SSSE3    (1 << 9)
#define CPUID_EXT_CID      (1 << 10)
#define CPUID_EXT_CX16     (1 << 13)
#define CPUID_EXT_XTPR     (1 << 14)
#define CPUID_EXT_PDCM     (1 << 15)
#define CPUID_EXT_DCA      (1 << 18)
#define CPUID_EXT_SSE41    (1 << 19)
#define CPUID_EXT_SSE42    (1 << 20)
#define CPUID_EXT_X2APIC   (1 << 21)
#define CPUID_EXT_MOVBE    (1 << 22)
#define CPUID_EXT_POPCNT   (1 << 23)
#define CPUID_EXT_XSAVE    (1 << 26)
#define CPUID_EXT_OSXSAVE  (1 << 27)
#define CPUID_EXT_HYPERVISOR  (1 << 31)

#define CPUID_EXT2_SYSCALL (1 << 11)
#define CPUID_EXT2_MP      (1 << 19)
#define CPUID_EXT2_NX      (1 << 20)
#define CPUID_EXT2_MMXEXT  (1 << 22)
#define CPUID_EXT2_FFXSR   (1 << 25)
#define CPUID_EXT2_PDPE1GB (1 << 26)
#define CPUID_EXT2_RDTSCP  (1 << 27)
#define CPUID_EXT2_LM      (1 << 29)
#define CPUID_EXT2_3DNOWEXT (1 << 30)
#define CPUID_EXT2_3DNOW   (1 << 31)

#define CPUID_EXT3_LAHF_LM (1 << 0)
#define CPUID_EXT3_CMP_LEG (1 << 1)
#define CPUID_EXT3_SVM     (1 << 2)
#define CPUID_EXT3_EXTAPIC (1 << 3)
#define CPUID_EXT3_CR8LEG  (1 << 4)
#define CPUID_EXT3_ABM     (1 << 5)
#define CPUID_EXT3_SSE4A   (1 << 6)
#define CPUID_EXT3_MISALIGNSSE (1 << 7)
#define CPUID_EXT3_3DNOWPREFETCH (1 << 8)
#define CPUID_EXT3_OSVW    (1 << 9)
#define CPUID_EXT3_IBS     (1 << 10)
#define CPUID_EXT3_SKINIT  (1 << 12)

#define CPUID_SVM_NPT          (1 << 0)
#define CPUID_SVM_LBRV         (1 << 1)
#define CPUID_SVM_SVMLOCK      (1 << 2)
#define CPUID_SVM_NRIPSAVE     (1 << 3)
#define CPUID_SVM_TSCSCALE     (1 << 4)
#define CPUID_SVM_VMCBCLEAN    (1 << 5)
#define CPUID_SVM_FLUSHASID    (1 << 6)
#define CPUID_SVM_DECODEASSIST (1 << 7)
#define CPUID_SVM_PAUSEFILTER  (1 << 10)
#define CPUID_SVM_PFTHRESHOLD  (1 << 12)

#define CPUID_VENDOR_INTEL_1 0x756e6547 /* "Genu" */
#define CPUID_VENDOR_INTEL_2 0x49656e69 /* "ineI" */
#define CPUID_VENDOR_INTEL_3 0x6c65746e /* "ntel" */

#define CPUID_VENDOR_AMD_1   0x68747541 /* "Auth" */
#define CPUID_VENDOR_AMD_2   0x69746e65 /* "enti" */
#define CPUID_VENDOR_AMD_3   0x444d4163 /* "cAMD" */

#define CPUID_VENDOR_VIA_1   0x746e6543 /* "Cent" */
#define CPUID_VENDOR_VIA_2   0x48727561 /* "aurH" */
#define CPUID_VENDOR_VIA_3   0x736c7561 /* "auls" */

#define CPUID_MWAIT_IBE     (1 << 1) /* Interrupts can exit capability */
#define CPUID_MWAIT_EMX     (1 << 0) /* enumeration supported */

/* i386-specific interrupt pending bits.  */
#define CPU_INTERRUPT_SMI       CPU_INTERRUPT_TGT_EXT_2
#define CPU_INTERRUPT_NMI       CPU_INTERRUPT_TGT_EXT_3
#define CPU_INTERRUPT_MCE       CPU_INTERRUPT_TGT_EXT_4
#define CPU_INTERRUPT_VIRQ      CPU_INTERRUPT_TGT_INT_0
#define CPU_INTERRUPT_INIT      CPU_INTERRUPT_TGT_INT_1
#define CPU_INTERRUPT_SIPI      CPU_INTERRUPT_TGT_INT_2

enum {
	CC_OP_DYNAMIC, /* must use dynamic code to get cc_op */
	CC_OP_EFLAGS,  /* all cc are explicitly computed, CC_SRC = flags */

	CC_OP_MULB, /* modify all flags, C, O = (CC_SRC != 0) */
	CC_OP_MULW,
	CC_OP_MULL,
	CC_OP_MULQ,

	CC_OP_ADDB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
	CC_OP_ADDW,
	CC_OP_ADDL,
	CC_OP_ADDQ,

	CC_OP_ADCB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
	CC_OP_ADCW,
	CC_OP_ADCL,
	CC_OP_ADCQ,

	CC_OP_SUBB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
	CC_OP_SUBW,
	CC_OP_SUBL,
	CC_OP_SUBQ,

	CC_OP_SBBB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
	CC_OP_SBBW,
	CC_OP_SBBL,
	CC_OP_SBBQ,

	CC_OP_LOGICB, /* modify all flags, CC_DST = res */
	CC_OP_LOGICW,
	CC_OP_LOGICL,
	CC_OP_LOGICQ,

	CC_OP_INCB, /* modify all flags except, CC_DST = res, CC_SRC = C */
	CC_OP_INCW,
	CC_OP_INCL,
	CC_OP_INCQ,

	CC_OP_DECB, /* modify all flags except, CC_DST = res, CC_SRC = C  */
	CC_OP_DECW,
	CC_OP_DECL,
	CC_OP_DECQ,

	CC_OP_SHLB, /* modify all flags, CC_DST = res, CC_SRC.msb = C */
	CC_OP_SHLW,
	CC_OP_SHLL,
	CC_OP_SHLQ,

	CC_OP_SARB, /* modify all flags, CC_DST = res, CC_SRC.lsb = C */
	CC_OP_SARW,
	CC_OP_SARL,
	CC_OP_SARQ,

	CC_OP_NB,
};

typedef struct x86_segment SegmentCache;

typedef union {
	uint8_t _b[16];
	uint16_t _w[8];
	uint32_t _l[4];
	uint64_t _q[2];
	float32 _s[4];
	float64 _d[2];
} XMMReg;

typedef union {
	uint8_t _b[8];
	uint16_t _w[4];
	uint32_t _l[2];
	float32 _s[2];
	uint64_t q;
} MMXReg;

#define XMM_B(n) _b[n]
#define XMM_W(n) _w[n]
#define XMM_L(n) _l[n]
#define XMM_S(n) _s[n]
#define XMM_Q(n) _q[n]
#define XMM_D(n) _d[n]

#define MMX_B(n) _b[n]
#define MMX_W(n) _w[n]
#define MMX_L(n) _l[n]
#define MMX_S(n) _s[n]
#define MMX_Q(n) q

typedef union {
	floatx80 d __declspec_align(16);
	MMXReg mmx;
} FPReg;

typedef struct {
	uint64_t base;
	uint64_t mask;
} MTRRVar;

#define NB_MMU_MODES 2

typedef struct CPUX86State {
	struct x86_env;

	/* emulator internal eflags handling */
	target_ulong cc_src;
	target_ulong cc_dst;
	uint32_t cc_op;
	int32_t df; /* D flag : 1 if D = 0, -1 if D = 1 */
	uint32_t hflags; /* TB flags, see HF_xxx constants. These flags
			    are known at translation time. */
	uint32_t hflags2; /* various other flags, see HF2_xxx constants. */

	/* segments */
	SegmentCache ldt;
	SegmentCache tr;
	SegmentCache gdt; /* only base and limit are used */
	SegmentCache idt; /* only base and limit are used */

	/* FPU state */
	unsigned int fpstt; /* top of stack index */
	uint16_t fpus;
	uint16_t fpuc;
	uint8_t fptags[8];   /* 0 = valid, 1 = empty */
	FPReg fpregs[8];
	/* KVM-only so far */
	uint16_t fpop;
	uint64_t fpip;
	uint64_t fpdp;

	/* emulator internal variables */
	float_status fp_status;
	floatx80 ft0;

	float_status mmx_status; /* for 3DNow! float ops */
	float_status sse_status;
	uint32_t mxcsr;
	XMMReg xmm_regs[CPU_NB_REGS];
	XMMReg xmm_t0;
	MMXReg mmx_t0;
	target_ulong cc_tmp; /* temporary for rcr/rcl */

	/* sysenter registers */
	uint32_t sysenter_cs;
	target_ulong sysenter_esp;
	target_ulong sysenter_eip;
	uint64_t efer;
	uint64_t star;

	uint64_t tsc_offset;
	uint64_t intercept;

#ifdef TARGET_X86_64
	target_ulong lstar;
	target_ulong cstar;
	target_ulong fmask;
	target_ulong kernelgsbase;
#endif

	uint64_t tsc;

	/* exception/interrupt handling */
	int error_code;
	int exception_is_int;
	target_ulong exception_next_eip;
	union {
		CPUBreakpoint *cpu_breakpoint[4];
		CPUWatchpoint *cpu_watchpoint[4];
	}; /* break/watchpoints for dr[0..3] */
	uint32_t smbase;
	int old_exception;  /* exception in flight */

	struct TranslationBlock *current_tb; /* currently executing TB  */
	/* soft mmu support */
	/* in order to avoid passing too many arguments to the MMIO
	   helpers, we store some rarely used information in the CPU
	   context) */
	unsigned long mem_io_pc; /* host pc at which the memory was
				    accessed */
	uint32_t halted; /* Nonzero if the CPU is in suspend state */
	uint32_t interrupt_request;
	uint32_t exit_request;

	/* The meaning of the MMU modes is defined in the target code. */
	CPUTLBEntry tlb_table[NB_MMU_MODES][CPU_TLB_SIZE];
	target_phys_addr_t iotlb[NB_MMU_MODES][CPU_TLB_SIZE];
	target_ulong tlb_flush_addr;
	target_ulong tlb_flush_mask;

	struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];
	/* buffer for temporaries in the code generator */
	long temp_buf[CPU_TEMP_BUF_NLONGS];

	int64_t icount_extra; /* Instructions until next timer event. */
	/* Number of cycles left, with interrupt flag in high bit.
	   This allows a single read-compare-cbranch-write sequence to test
	   for both decrementer underflow and exceptions.  */
	union {
		uint32_t u32;
		icount_decr_u16 u16;
	} icount_decr;
	uint32_t can_do_io; /* nonzero if memory mapped IO is safe. */

	/* from this point: preserved by CPU reset */
	/* ice debug support */
	QTAILQ_HEAD(breakpoints_head, CPUBreakpoint) breakpoints;
	int singlestep_enabled;

	QTAILQ_HEAD(watchpoints_head, CPUWatchpoint) watchpoints;
	CPUWatchpoint *watchpoint_hit;

	/* Core interrupt code */
	jmp_buf *jmp_env;
	int exception_index;

	int nr_cores;  /* number of cores within this CPU package */
	int nr_threads;/* number of threads within this CPU */
	int running; /* Nonzero if cpu is currently running(usermode).  */
	/* user data */
	void *opaque;

	uint64_t pat;

	/* processor features (e.g. for CPUID insn) */
	uint32_t cpuid_level;
	uint32_t cpuid_vendor1;
	uint32_t cpuid_vendor2;
	uint32_t cpuid_vendor3;
	uint32_t cpuid_version;
	uint32_t cpuid_features;
	uint32_t cpuid_ext_features;
	uint32_t cpuid_xlevel;
	uint32_t cpuid_model[12];
	uint32_t cpuid_ext2_features;
	uint32_t cpuid_ext3_features;
	uint32_t cpuid_apic_id;
	/* Store the results of Centaur's CPUID instructions */
	uint32_t cpuid_xlevel2;
	uint32_t cpuid_ext4_features;

	/* MTRRs */
	uint64_t mtrr_fixed[11];
	uint64_t mtrr_deftype;
	MTRRVar mtrr_var[8];

	/* For KVM */
	uint8_t has_error_code;
	uint32_t sipi_vector;

	uint64_t mcg_cap;
	uint64_t mcg_ctl;
	uint64_t mce_banks[MCE_BANKS_DEF*4];

	uint64_t tsc_aux;

	/* do not use this buffer directly */
	jmp_buf env_jmp_buf;
} CPUX86State;

CPUX86State *cpu_x86_init(void);
int cpu_x86_exec(CPUX86State *s);
void cpu_x86_close(CPUX86State *s);
int cpu_x86_support_mca_broadcast(CPUState *env);

/* this function must always be used to load data in the segment
   cache: it synchronizes the hflags with the segment cache values */
__INLINE__ void cpu_x86_load_seg_cache(CPUX86State *env,
				       int seg_reg, unsigned int selector,
				       target_ulong base,
				       unsigned int limit,
				       unsigned int flags)
{
	SegmentCache *sc;
	unsigned int new_hflags;

	sc = &env->segs[seg_reg];
	sc->selector = selector;
	sc->base = base;
	sc->limit = limit;
	sc->flags = flags;

	/* update the hidden flags */
	{
		if (seg_reg == R_CS) {
#ifdef TARGET_X86_64
			if ((env->hflags & HF_LMA_MASK) && (flags & DESC_L_MASK)) {
				/* long mode */
				env->hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK;
				env->hflags &= ~(HF_ADDSEG_MASK);
			} else
#endif
			{
				/* legacy / compatibility case */
				new_hflags = (env->segs[R_CS].flags & DESC_B_MASK)
					>> (DESC_B_SHIFT - HF_CS32_SHIFT);
				env->hflags = (env->hflags & ~(HF_CS32_MASK | HF_CS64_MASK)) |
					new_hflags;
			}
		}
		new_hflags = (env->segs[R_SS].flags & DESC_B_MASK)
			>> (DESC_B_SHIFT - HF_SS32_SHIFT);
		if (env->hflags & HF_CS64_MASK) {
			/* zero base assumed for DS, ES and SS in long mode */
		} else if (!(env->cr[0] & CR0_PE_MASK) ||
			   (env->eflags & VM_MASK) ||
			   !(env->hflags & HF_CS32_MASK)) {
			/* XXX: try to avoid this test. The problem comes from the
			   fact that is real mode or vm86 mode we only modify the
			   'base' and 'selector' fields of the segment cache to go
			   faster. A solution may be to force addseg to one in
			   translate-i386.c. */
			new_hflags |= HF_ADDSEG_MASK;
		} else {
			new_hflags |= ((env->segs[R_DS].base |
					env->segs[R_ES].base |
					env->segs[R_SS].base) != 0) <<
				HF_ADDSEG_SHIFT;
		}
		env->hflags = (env->hflags &
			       ~(HF_SS32_MASK | HF_ADDSEG_MASK)) | new_hflags;
	}
}

__INLINE__ void cpu_x86_load_seg_cache_sipi(CPUX86State *env,
					    int sipi_vector)
{
	env->eip = 0;
	cpu_x86_load_seg_cache(env, R_CS, sipi_vector << 8,
			       sipi_vector << 12,
			       env->segs[R_CS].limit,
			       env->segs[R_CS].flags);
	env->halted = 0;
}

int cpu_x86_get_descr_debug(CPUX86State *env, unsigned int selector,
                            target_ulong *base, unsigned int *limit,
                            unsigned int *flags);

/* wrapper, just in case memory mappings must be changed */
__INLINE__ void cpu_x86_set_cpl(CPUX86State *s, int cpl)
{
#if HF_CPL_MASK == 3
	s->hflags = (s->hflags & ~HF_CPL_MASK) | cpl;
#else
#error HF_CPL_MASK is hardcoded
#endif
}

/* cpu-exec.c */
/* the following helpers are only usable in user mode simulation as
   they can trigger unexpected exceptions */
void cpu_x86_load_seg(CPUX86State *s, int seg_reg, int selector);

/* cpuid.c */
void cpu_x86_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
                   uint32_t *eax, uint32_t *ebx,
                   uint32_t *ecx, uint32_t *edx);
int cpu_x86_register (CPUX86State *env);
void host_cpuid(uint32_t function, uint32_t count,
                uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx);

__INLINE__ int hw_breakpoint_enabled(unsigned long dr7, int index)
{
	return (dr7 >> (index * 2)) & 3;
}

__INLINE__ int hw_breakpoint_type(unsigned long dr7, int index)
{
	return (dr7 >> (DR7_TYPE_SHIFT + (index * 4))) & 3;
}

__INLINE__ int hw_breakpoint_len(unsigned long dr7, int index)
{
	int len = ((dr7 >> (DR7_LEN_SHIFT + (index * 4))) & 3);
	return (len == 2) ? 8 : len + 1;
}

__INLINE__ void hw_breakpoint_insert(CPUX86State *env, int index)
{
}

__INLINE__ void hw_breakpoint_remove(CPUX86State *env, int index)
{
}

__INLINE__ int check_hw_breakpoints(CPUX86State *env, int force_dr6_update)
{
	return 0;
}

/* will be suppressed */
void cpu_x86_update_cr0(CPUX86State *env, uint32_t new_cr0);
void cpu_x86_update_cr3(CPUX86State *env, target_ulong new_cr3);
void cpu_x86_update_cr4(CPUX86State *env, uint32_t new_cr4);

void cpu_smm_update(CPUX86State *env);
__INLINE__ uint64_t cpu_get_tsc(CPUX86State *env)
{
	// TODO:
	return 0;
}

/* used to debug */
#define X86_DUMP_FPU  0x0001 /* dump FPU state too */
#define X86_DUMP_CCOP 0x0002 /* dump qemu flag cache */

#define TARGET_PAGE_BITS 12

#ifdef TARGET_X86_64
#define TARGET_PHYS_ADDR_SPACE_BITS 52
/* ??? This is really 48 bits, sign-extended, but the only thing
   accessible to userland with bit 48 set is the VSYSCALL, and that
   is handled via other mechanisms.  */
#define TARGET_VIRT_ADDR_SPACE_BITS 47
#else
#define TARGET_PHYS_ADDR_SPACE_BITS 36
#define TARGET_VIRT_ADDR_SPACE_BITS 32
#endif

#define cpu_init cpu_x86_init
#define cpu_exec cpu_x86_exec
#define cpu_gen_code cpu_x86_gen_code

/* #define CPU_SAVE_VERSION 12 */

/* MMU modes definitions */
#define MMU_MODE0_SUFFIX _kernel
#define MMU_MODE1_SUFFIX _user
#define MMU_USER_IDX 1
__INLINE__ int cpu_mmu_index (CPUState *env)
{
	return (env->hflags & HF_CPL_MASK) == 3 ? 1 : 0;
}

#undef EAX
#define EAX (env->regs[R_EAX])
#undef ECX
#define ECX (env->regs[R_ECX])
#undef EDX
#define EDX (env->regs[R_EDX])
#undef EBX
#define EBX (env->regs[R_EBX])
#undef ESP
#define ESP (env->regs[R_ESP])
#undef EBP
#define EBP (env->regs[R_EBP])
#undef ESI
#define ESI (env->regs[R_ESI])
#undef EDI
#define EDI (env->regs[R_EDI])
#undef EIP
#define EIP (env->eip)
#define DF  (env->df)

#define CC_SRC (env->cc_src)
#define CC_DST (env->cc_dst)
#define CC_OP  (env->cc_op)

/* float macros */
#define FT0    (env->ft0)
#define ST0    (env->fpregs[env->fpstt].d)
#define ST(n)  (env->fpregs[(env->fpstt + (n)) & 7].d)
#define ST1    ST(1)

/* translate.c */
void optimize_flags_init(void);

typedef struct CCTable {
	int (*compute_all)(void); /* return all the flags */
	int (*compute_c)(void);  /* return the C flag */
} CCTable;

#if defined(CONFIG_USER_ONLY)
__INLINE__ void cpu_clone_regs(CPUState *env, target_ulong newsp)
{
	if (newsp)
		env->regs[R_ESP] = newsp;
	env->regs[R_EAX] = 0;
}
#endif

#include "cpu-all.h"
#include "svm.h"

__INLINE__ bool_t cpu_has_work(CPUState *env)
{
	return ((env->interrupt_request & CPU_INTERRUPT_HARD) &&
		(env->eflags & IF_MASK)) ||
		(env->interrupt_request & (CPU_INTERRUPT_NMI |
					   CPU_INTERRUPT_INIT |
					   CPU_INTERRUPT_SIPI |
					   CPU_INTERRUPT_MCE));
}

#include "exec-all.h"

__INLINE__ void cpu_pc_from_tb(CPUState *env, TranslationBlock *tb)
{
	env->eip = tb->pc - tb->cs_base;
}

__INLINE__ void cpu_get_tb_cpu_state(CPUState *env, target_ulong *pc,
				     target_ulong *cs_base, int *flags)
{
	*cs_base = env->segs[R_CS].base;
	*pc = *cs_base + env->eip;
	*flags = env->hflags |
		(env->eflags & (IOPL_MASK | TF_MASK | RF_MASK | VM_MASK));
}

void do_cpu_init(CPUState *env);
void do_cpu_sipi(CPUState *env);

#define MCE_INJECT_BROADCAST    1
#define MCE_INJECT_UNCOND_AO    2

/* op_helper.c */
void do_interrupt(CPUState *env);
void do_interrupt_x86_hardirq(CPUState *env, int intno, int is_hw);

void do_smm_enter(CPUState *env1);

void svm_check_intercept(CPUState *env1, uint32_t type);

uint32_t cpu_cc_compute_all(CPUState *env1, int op);

#pragma pack (pop)

#endif /* CPU_I386_H */
