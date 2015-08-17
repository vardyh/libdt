#include <ctor.h>
#include <container/list.h>

#ifndef _VXENG_H_
#define _VXENG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define R_EAX 0
#define R_ECX 1
#define R_EDX 2
#define R_EBX 3
#define R_ESP 4
#define R_EBP 5
#define R_ESI 6
#define R_EDI 7

#define R_AL 0
#define R_CL 1
#define R_DL 2
#define R_BL 3
#define R_AH 4
#define R_CH 5
#define R_DH 6
#define R_BH 7

#define R_ES 0
#define R_CS 1
#define R_SS 2
#define R_DS 3
#define R_FS 4
#define R_GS 5

#define CC_C   	0x0001
#define CC_P 	0x0004
#define CC_A	0x0010
#define CC_Z	0x0040
#define CC_S    0x0080
#define CC_O    0x0800

#define TF_SHIFT   8
#define IOPL_SHIFT 12
#define VM_SHIFT   17

#define ZF_MASK		0x00000040
#define TF_MASK 	0x00000100
#define IF_MASK 	0x00000200
#define DF_MASK 	0x00000400
#define IOPL_MASK	0x00003000
#define NT_MASK	        0x00004000
#define RF_MASK		0x00010000
#define VM_MASK		0x00020000
#define AC_MASK		0x00040000
#define VIF_MASK        0x00080000
#define VIP_MASK        0x00100000
#define ID_MASK         0x00200000

#define CR0_PE_SHIFT 0
#define CR0_MP_SHIFT 1

#define CR0_PE_MASK  (1 << 0)
#define CR0_MP_MASK  (1 << 1)
#define CR0_EM_MASK  (1 << 2)
#define CR0_TS_MASK  (1 << 3)
#define CR0_ET_MASK  (1 << 4)
#define CR0_NE_MASK  (1 << 5)
#define CR0_WP_MASK  (1 << 16)
#define CR0_AM_MASK  (1 << 18)
#define CR0_PG_MASK  (1 << 31)

#define CR4_VME_MASK  (1 << 0)
#define CR4_PVI_MASK  (1 << 1)
#define CR4_TSD_MASK  (1 << 2)
#define CR4_DE_MASK   (1 << 3)
#define CR4_PSE_MASK  (1 << 4)
#define CR4_PAE_MASK  (1 << 5)
#define CR4_MCE_MASK  (1 << 6)
#define CR4_PGE_MASK  (1 << 7)
#define CR4_PCE_MASK  (1 << 8)
#define CR4_OSFXSR_SHIFT 9
#define CR4_OSFXSR_MASK (1 << CR4_OSFXSR_SHIFT)
#define CR4_OSXMMEXCPT_MASK  (1 << 10)
#define CR4_SMEP_MASK (1 << 20)

#define DR6_BD          (1 << 13)
#define DR6_BS          (1 << 14)
#define DR6_BT          (1 << 15)
#define DR6_FIXED_1     0xffff0ff0

#define DR7_GD          (1 << 13)
#define DR7_TYPE_SHIFT  16
#define DR7_LEN_SHIFT   18
#define DR7_FIXED_1     0x00000400

#define PG_P_BIT       	0
#define PG_RW_BIT      	1
#define PG_US_BIT      	2
#define PG_PWT_BIT     	3
#define PG_PCD_BIT     	4
#define PG_A_BIT       	5
#define PG_D_BIT       	6
#define PG_PS_BIT      	7
#define PG_G_BIT       	8
#define PG_NX_BIT       63

#define PG_P_MASK      	(1 << PG_P_BIT)
#define PG_RW_MASK     	(1 << PG_RW_BIT)
#define PG_US_MASK     	(1 << PG_US_BIT)
#define PG_PWT_MASK    	(1 << PG_PWT_BIT)
#define PG_PCD_MASK    	(1 << PG_PCD_BIT)
#define PG_A_MASK      	(1 << PG_A_BIT)
#define PG_D_MASK      	(1 << PG_D_BIT)
#define PG_PS_MASK     	(1 << PG_PS_BIT)
#define PG_G_MASK      	(1 << PG_G_BIT)
#define PG_NX_MASK     	(1ULL << PG_NX_BIT)

/* MSRs */
#define MSR_SYSENTER_CS		0x174
#define MSR_SYSENTER_ESP	0x175
#define MSR_SYSENTER_EIP	0x176
#define MSR_IA32_EFER		0xc0000080
#define MSR_IA32_FSBASE		0xc0000100
#define MSR_IA32_GSBASE		0xc0000101
#define MSR_IA32_KERNEL_GSBASE	0xc0000102
#ifndef MSR_IA32_APICBASE
# define MSR_IA32_APICBASE	0x1b
#endif

#define EFER_SYSCALL_MASK (1 << 0)
#define EFER_XD_MASK (1 << 11)

#define APIC_LVR	0x30
#define APIC_LVT_CMCI	0x2f0

#define MSR_X2APIC_LVR	0x803
#define MSR_X2APIC_LVT_CMCI 0x82f

#define APIC_DM_MASK	0x00700
#define APIC_DM_NMI	0x00400
#define APIC_LVT_MASKED	(1 << 16)

/* error code used inside vxeng */
#define EXCP_INTERRUPT 	0x10000 /* async interruption */
#define EXCP_HLT        0x10001 /* hlt instruction reached */
#define EXCP_DEBUG      0x10002 /* cpu stopped after a breakpoint or singlestep */
#define EXCP_HALTED     0x10003 /* cpu is halted (waiting for external event) */
#define EXCP_LIMIT      0x10004 /* run limit exceeded */
#define EXCP_SMC	0x10005 /* running into self-modified code */
#define EXCP_CROSS_VMA	0x10006 /* running across vmas */
#define EXCP_SPAN_VMA	0x10007 /* running span vmas */
#define EXCP_PAUSE	0x10008 /* pause execution */

#define EXCP00_DIVZ	0
#define EXCP01_DB	1
#define EXCP02_NMI	2
#define EXCP03_INT3	3
#define EXCP04_INTO	4
#define EXCP05_BOUND	5
#define EXCP06_ILLOP	6
#define EXCP07_PREX	7
#define EXCP08_DBLE	8
#define EXCP09_XERR	9
#define EXCP0A_TSS	10
#define EXCP0B_NOSEG	11
#define EXCP0C_STACK	12
#define EXCP0D_GPF	13
#define EXCP0E_PAGE	14
#define EXCP10_COPR	16
#define EXCP11_ALGN	17
#define EXCP12_MCHK	18
#define EXCP_SYSENTER  	0x30
#define EXCP_SYSCALL    0x80
#define EXCP_VMCI    	0x81

#pragma pack (push, 1)

union x86_reg {
	uint8_t  b;
	uint16_t w;
	uint32_t l;
	uint64_t q;
	ptr64_t val;
	uintptr_t p;
};

struct x86_segment {
	uint32_t selector;
	ptr64_t base;
	uint32_t limit;
	uint32_t flags;
};

struct x86_float {
	uint64_t fraction;
	uint16_t exp;
	uint8_t __padding[6];
};

union x86_xmm_reg {
	int8_t _sbyte[16];
	int16_t _s16[8];
	int32_t _s32[4];
	int64_t _s64[2];
	uint8_t _ubyte[16];
	uint16_t _u16[8];
	uint32_t _u32[4];
	uint64_t _u64[2];
};

union x86_fpu {
	struct {
		uint16_t fcw;
		uint16_t fsw;
		uint16_t ftw;
		uint16_t fop;
		uint32_t fpu_ip;
		uint16_t cs;
		uint16_t __rsvrd_0;
		uint32_t fpu_dp;
		uint16_t ds;
		uint16_t __rsvrd_1;
		uint32_t mxcsr;
		uint32_t mxcsr_mask;
		struct x86_float st[8];
		union x86_xmm_reg xmm[16];
	} ctx;
	uint8_t place_holder[512];
};

struct x86_tss {
	uint16_t prev_link, __prevlnk_h;
	uint32_t esp0;
	uint16_t ss0, __ss0_h;
	uint32_t esp1;
	uint16_t ss1, __ss1_h;
	uint32_t esp2;
	uint16_t ss2, __ss2_h;
	uint32_t pdbr;
	uint32_t eip;
	uint32_t eflags;
	uint32_t eax;
	uint32_t ecx;
	uint32_t edx;
	uint32_t ebx;
	uint32_t esp;
	uint32_t ebp;
	uint32_t esi;
	uint32_t edi;
	uint16_t es, __es_h;
	uint16_t cs, __cs_h;
	uint16_t ss, __ss_h;
	uint16_t ds, __ds_h;
	uint16_t fs, __fs_h;
	uint16_t gs, __gs_h;
	uint16_t ldt_sel, __ldt_sel_h;
	uint16_t trace, io_bitmap;
};

struct x86_tss64 {
	uint32_t __rsvrd_0;
	uint64_t esp0;
	uint64_t esp1;
	uint64_t esp2;
	uint64_t __rsvrd_1;
	uint64_t ist[7];
	uint64_t __rsvrd_2;
	uint16_t __rsvrd_3;
	uint16_t io_bitmap;
};

struct x86_xdtr {
	uint16_t limit;
	uint32_t base;
};

struct x86_xdtr64 {
	uint16_t limit;
	uint64_t base;
};

struct x86_env {
	union x86_fpu fpu;
	union x86_reg regs[16];
	union x86_reg eip;
	union x86_reg eflags;
	struct x86_segment segs[6];
	union x86_reg cr[5];
	union x86_reg dr[8];
	uint32_t error_code;
};

#pragma pack (pop)

#undef CS
#undef DS
#undef ES
#undef SS
#undef FS
#undef GS

#undef EAX
#undef ECX
#undef EDX
#undef EBX
#undef ESP
#undef EBP
#undef ESI
#undef EDI

#undef EIP
#undef EFL

#define CS ((env)->segs[R_CS])
#define DS ((env)->segs[R_DS])
#define ES ((env)->segs[R_ES])
#define SS ((env)->segs[R_SS])
#define FS ((env)->segs[R_FS])
#define GS ((env)->segs[R_GS])

#define EAX ((env)->regs[R_EAX].val)
#define ECX ((env)->regs[R_ECX].val)
#define EDX ((env)->regs[R_EDX].val)
#define EBX ((env)->regs[R_EBX].val)
#define ESP ((env)->regs[R_ESP].val)
#define EBP ((env)->regs[R_EBP].val)
#define ESI ((env)->regs[R_ESI].val)
#define EDI ((env)->regs[R_EDI].val)

#define EIP ((env)->eip.val)
#define EFL ((env)->eflags.val)
#define FLT ((env)->fpu.ctx)

#define CR0 ((env)->cr[0].val)
#define CR2 ((env)->cr[2].val)
#define CR3 ((env)->cr[3].val)
#define CR4 ((env)->cr[4].val)

#define DR0 ((env)->dr[0].val)
#define DR1 ((env)->dr[1].val)
#define DR2 ((env)->dr[2].val)
#define DR3 ((env)->dr[3].val)
#define DR6 ((env)->dr[6].val)
#define DR7 ((env)->dr[7].val)

#define ERRCODE ((env)->error_code)

struct vxeng;

struct vxeng_callouts {
	int (EXPORT_DECL *vmread)(struct vxeng *, ptr64_t vaddr, void *buffer, int length);
	int (EXPORT_DECL *vmwrite)(struct vxeng *, ptr64_t vaddr, const void *buffer, int length);
};

struct vxeng {
	struct vxeng_callouts callouts;
	void *opaque;
};

struct vxeng_class {
	const char *name;
	struct vxeng *(EXPORT_DECL *alloc)(void);
	struct list_head next;
};

void EXPORT_DECL vxeng_register(struct vxeng_class *);

#ifdef __cplusplus
}
#endif

#endif /* _VXENG_H_ */
