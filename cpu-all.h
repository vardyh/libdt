/*
 * defines common to all virtual CPUs
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
#ifndef CPU_ALL_H
#define CPU_ALL_H

#include "qemu-common.h"
#include "softmmu_defs.h"
#include "softfloat.h"

extern int use_icount;

/* Deterministic execution requires that IO only be performed on the last
   instruction of a TB so that interrupts take effect immediately.  */
__INLINE__ int can_do_io(CPUState *env)
{
    if (!use_icount)
        return 1;

    /* If not executing code then assume we are ok.  */
    if (!env->current_tb)
        return 1;

    return env->can_do_io != 0;
}

typedef union {
    float32 f;
    uint32_t l;
} CPU_FloatU;

/* NOTE: arm FPA is horrible as double 32 bit words are stored in big
   endian ! */
typedef union {
    float64 d;
    struct {
        uint32_t lower;
        uint32_t upper;
    } l;
    uint64_t ll;
} CPU_DoubleU;

typedef union {
     floatx80 d;
     struct {
         uint64_t lower;
         uint16_t upper;
     } l;
} CPU_LDoubleU;

typedef union {
    float128 q;
    struct {
        uint32_t lowest;
        uint32_t lower;
        uint32_t upper;
        uint32_t upmost;
    } l;
    struct {
        uint64_t lower;
        uint64_t upper;
    } ll;
} CPU_QuadU;

/* CPU memory access without any memory or io remapping */

/*
 * the generic syntax for the memory accesses is:
 *
 * load: ld{type}{sign}{size}{endian}_{access_type}(ptr)
 *
 * store: st{type}{size}{endian}_{access_type}(ptr, val)
 *
 * type is:
 * (empty): integer access
 *   f    : float access
 *
 * sign is:
 * (empty): for floats or 32 bit size
 *   u    : unsigned
 *   s    : signed
 *
 * size is:
 *   b: 8 bits
 *   w: 16 bits
 *   l: 32 bits
 *   q: 64 bits
 *
 * endian is:
 * (empty): target cpu endianness or 8 bit access
 *   r    : reversed target cpu endianness (not implemented yet)
 *   be   : big endian (not implemented yet)
 *   le   : little endian (not implemented yet)
 *
 * access_type is:
 *   raw    : host memory access
 *   user   : user mode access using soft MMU
 *   kernel : kernel mode access using soft MMU
 */
__INLINE__ int ldub_p(const void *ptr)
{
    return *(uint8_t *) ptr;
}

__INLINE__ int ldsb_p(const void *ptr)
{
    return *(int8_t *) ptr;
}

__INLINE__ void stb_p(void *ptr, int v)
{
    *(uint8_t *) ptr = v;
}

__INLINE__ int lduw_p(const void *ptr)
{
    return *(uint16_t *) ptr;
}

__INLINE__ int ldsw_p(const void *ptr)
{
    return *(int16_t *) ptr;
}

__INLINE__ int ldl_p(const void *ptr)
{
    return *(uint32_t *) ptr;
}

__INLINE__ uint64_t ldq_p(const void *ptr)
{
    return *(uint64_t *) ptr;
}

__INLINE__ void stw_p(void *ptr, int v)
{
    *(uint16_t *) ptr = v;
}

__INLINE__ void stl_p(void *ptr, int v)
{
    *(uint32_t *) ptr = v;
}

__INLINE__ void stq_p(void *ptr, uint64_t v)
{
    *(uint64_t *) ptr = v;
}

/* MMU memory access macros */
#define ldub(p)   (uint8_t)  __ldb_mmu(p, 1)
#define ldsb(p)   ( int8_t)  __ldb_mmu(p, 1)
#define lduw(p)   (uint16_t) __ldw_mmu(p, 1)
#define ldsw(p)   ( int16_t) __ldw_mmu(p, 1)
#define ldl(p)    (uint32_t) __ldl_mmu(p, 1)
#define ldq(p)    (uint64_t) __ldq_mmu(p, 1)
#define stb(p, v) (void)     __stb_mmu(p, v, 1)
#define stw(p, v) (void)     __stw_mmu(p, v, 1)
#define stl(p, v) (void)     __stl_mmu(p, v, 1)
#define stq(p, v) (void)     __stq_mmu(p, v, 1)

#define ldub_code(p) (uint8_t)  __ldb_mmu(p, -1)
#define ldsb_code(p) ( int8_t)  __ldb_mmu(p, -1)
#define lduw_code(p) (uint16_t) __ldw_mmu(p, -1)
#define ldsw_code(p) ( int16_t) __ldw_mmu(p, -1)
#define ldl_code(p)  (uint32_t) __ldl_mmu(p, -1)
#define ldq_code(p)  (uint64_t) __ldq_mmu(p, -1)

#define ldub_kernel(p)   (uint8_t)  __ldb_mmu(p, 0)
#define ldsb_kernel(p)   ( int8_t)  __ldb_mmu(p, 0)
#define lduw_kernel(p)   (uint16_t) __ldw_mmu(p, 0)
#define ldsw_kernel(p)   ( int16_t) __ldw_mmu(p, 0)
#define ldl_kernel(p)    (uint32_t) __ldl_mmu(p, 0)
#define ldq_kernel(p)    (uint64_t) __ldq_mmu(p, 0)
#define stb_kernel(p, v) (void)     __stb_mmu(p, v, 0)
#define stw_kernel(p, v) (void)     __stw_mmu(p, v, 0)
#define stl_kernel(p, v) (void)     __stl_mmu(p, v, 0)
#define stq_kernel(p, v) (void)     __stq_mmu(p, v, 0)

/* page related stuff */

#define TARGET_PAGE_SIZE (1 << TARGET_PAGE_BITS)
#define TARGET_PAGE_MASK ~(TARGET_PAGE_SIZE - 1)
#define TARGET_PAGE_ALIGN(addr) (((addr) + TARGET_PAGE_SIZE - 1) & TARGET_PAGE_MASK)

/* ??? These should be the larger of unsigned long and target_ulong.  */
extern unsigned long qemu_real_host_page_size;
extern unsigned long qemu_host_page_bits;
extern unsigned long qemu_host_page_size;
extern unsigned long qemu_host_page_mask;

#define HOST_PAGE_ALIGN(addr) (((addr) + qemu_host_page_size - 1) & qemu_host_page_mask)

/* same as PROT_xxx */
#define PAGE_READ      0x0001
#define PAGE_WRITE     0x0002
#define PAGE_EXEC      0x0004
#define PAGE_BITS      (PAGE_READ | PAGE_WRITE | PAGE_EXEC)
#define PAGE_VALID     0x0008
/* original state of the write flag (used when tracking self-modifying
   code */
#define PAGE_WRITE_ORG 0x0010

#define cpu_abort(env, ...) do { cpu_loop_exit(env); } while (0)

extern CPUState *cpu_single_env;

/* Flags for use in ENV->INTERRUPT_PENDING.

   The numbers assigned here are non-sequential in order to preserve
   binary compatibility with the vmstate dump.  Bit 0 (0x0001) was
   previously used for CPU_INTERRUPT_EXIT, and is cleared when loading
   the vmstate dump.  */

/* External hardware interrupt pending.  This is typically used for
   interrupts from devices.  */
#define CPU_INTERRUPT_HARD        0x0002

/* Exit the current TB.  This is typically used when some system-level device
   makes some change to the memory mapping.  E.g. the a20 line change.  */
#define CPU_INTERRUPT_EXITTB      0x0004

/* Halt the CPU.  */
#define CPU_INTERRUPT_HALT        0x0020

/* Debug event pending.  */
#define CPU_INTERRUPT_DEBUG       0x0080

/* Several target-specific external hardware interrupts.  Each target/cpu.h
   should define proper names based on these defines.  */
#define CPU_INTERRUPT_TGT_EXT_0   0x0008
#define CPU_INTERRUPT_TGT_EXT_1   0x0010
#define CPU_INTERRUPT_TGT_EXT_2   0x0040
#define CPU_INTERRUPT_TGT_EXT_3   0x0200
#define CPU_INTERRUPT_TGT_EXT_4   0x1000

/* Several target-specific internal interrupts.  These differ from the
   preceeding target-specific interrupts in that they are intended to
   originate from within the cpu itself, typically in response to some
   instruction being executed.  These, therefore, are not masked while
   single-stepping within the debugger.  */
#define CPU_INTERRUPT_TGT_INT_0   0x0100
#define CPU_INTERRUPT_TGT_INT_1   0x0400
#define CPU_INTERRUPT_TGT_INT_2   0x0800

/* First unused bit: 0x2000.  */

/* The set of all bits that should be masked when single-stepping.  */
#define CPU_INTERRUPT_SSTEP_MASK \
    (CPU_INTERRUPT_HARD          \
     | CPU_INTERRUPT_TGT_EXT_0   \
     | CPU_INTERRUPT_TGT_EXT_1   \
     | CPU_INTERRUPT_TGT_EXT_2   \
     | CPU_INTERRUPT_TGT_EXT_3   \
     | CPU_INTERRUPT_TGT_EXT_4)

void cpu_interrupt(CPUState *env, int mask);
void cpu_reset_interrupt(CPUState *env, int mask);
void cpu_exit(CPUState *s);

/* Breakpoint/watchpoint flags */
#define BP_MEM_READ           0x01
#define BP_MEM_WRITE          0x02
#define BP_MEM_ACCESS         (BP_MEM_READ | BP_MEM_WRITE)
#define BP_STOP_BEFORE_ACCESS 0x04
#define BP_WATCHPOINT_HIT     0x08
#define BP_GDB                0x10
#define BP_CPU                0x20

int cpu_breakpoint_insert(CPUState *env, target_ulong pc, int flags,
                          CPUBreakpoint **breakpoint);
int cpu_breakpoint_remove(CPUState *env, target_ulong pc, int flags);
void cpu_breakpoint_remove_by_ref(CPUState *env, CPUBreakpoint *breakpoint);
void cpu_breakpoint_remove_all(CPUState *env, int mask);
int cpu_watchpoint_insert(CPUState *env, target_ulong addr, target_ulong len,
                          int flags, CPUWatchpoint **watchpoint);
int cpu_watchpoint_remove(CPUState *env, target_ulong addr,
                          target_ulong len, int flags);
void cpu_watchpoint_remove_by_ref(CPUState *env, CPUWatchpoint *watchpoint);
void cpu_watchpoint_remove_all(CPUState *env, int mask);

#define SSTEP_ENABLE  0x1  /* Enable simulated HW single stepping */
#define SSTEP_NOIRQ   0x2  /* Do not use IRQ while single stepping */
#define SSTEP_NOTIMER 0x4  /* Do not Timers while single stepping */

void cpu_single_step(CPUState *env, int enabled);
void cpu_reset(CPUState *s);

#define CPU_LOG_TB_OUT_ASM (1 << 0)
#define CPU_LOG_TB_IN_ASM  (1 << 1)
#define CPU_LOG_TB_OP      (1 << 2)
#define CPU_LOG_TB_OP_OPT  (1 << 3)
#define CPU_LOG_INT        (1 << 4)
#define CPU_LOG_EXEC       (1 << 5)
#define CPU_LOG_PCALL      (1 << 6)
#define CPU_LOG_IOPORT     (1 << 7)
#define CPU_LOG_TB_CPU     (1 << 8)
#define CPU_LOG_RESET      (1 << 9)

#endif /* CPU_ALL_H */
