/*
 *  virtual page mapping and translated block handling
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

#include <assert.h>
#ifndef _WIN32
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "qemu-common.h"
#include "cpu.h"
#include "tcg.h"
#include "osdep.h"

#define SMC_BITMAP_USE_THRESHOLD 10

static TranslationBlock *tbs;
static int code_gen_max_blocks;
TranslationBlock *tb_phys_hash[CODE_GEN_PHYS_HASH_SIZE];
static int nb_tbs;
/* any access to the tbs or the page table must use this lock */
spinlock_t tb_lock = SPIN_LOCK_UNLOCKED;

#if defined(_WIN32)
/* Maximum alignment for Win32 is 16. */
#define code_gen_section \
	__declspec_align(16)
#else
#define code_gen_section \
	__declspec_align(32)
#endif

uint8_t code_gen_prologue[1024] code_gen_section;
static uint8_t *code_gen_buffer;
static unsigned long code_gen_buffer_size;
/* threshold to flush the translated code buffer */
static unsigned long code_gen_buffer_max_size;
static uint8_t *code_gen_ptr;

/* current CPU in the current thread. It is only valid inside
   cpu_exec() */
CPUState *cpu_single_env;
/* 0 = Do not count executed instructions.
   1 = Precise instruction counting.
   2 = Adaptive rate instruction counting.  */
int use_icount = 0;
/* Current instruction counter.  While executing translated code this may
   include some instructions that have not yet been executed.  */
int64_t qemu_icount;

typedef struct PageDesc {
	/* list of TBs intersecting this ram page */
	TranslationBlock *first_tb;
	/* in order to optimize self modifying code, we count the number
	   of lookups we do to a given page to use a bitmap */
	unsigned int code_write_count;
	uint8_t *code_bitmap;
#if defined(CONFIG_USER_ONLY)
	unsigned long flags;
#endif
} PageDesc;

/* In system mode we want L1_MAP to be based on ram offsets,
   while in user mode we want it to be based on virtual addresses.  */
#if !defined(CONFIG_USER_ONLY)
#if HOST_LONG_BITS < TARGET_PHYS_ADDR_SPACE_BITS
# define L1_MAP_ADDR_SPACE_BITS  HOST_LONG_BITS
#else
# define L1_MAP_ADDR_SPACE_BITS  TARGET_PHYS_ADDR_SPACE_BITS
#endif
#else
# define L1_MAP_ADDR_SPACE_BITS  TARGET_VIRT_ADDR_SPACE_BITS
#endif

/* Size of the L2 (and L3, etc) page tables.  */
#define L2_BITS 10
#define L2_SIZE (1 << L2_BITS)

/* The bits remaining after N lower levels of page tables.  */
#define P_L1_BITS_REM							\
	((TARGET_PHYS_ADDR_SPACE_BITS - TARGET_PAGE_BITS) % L2_BITS)
#define V_L1_BITS_REM						\
	((L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS) % L2_BITS)

/* Size of the L1 page table.  Avoid silly small sizes.  */
#if P_L1_BITS_REM < 4
#define P_L1_BITS  (P_L1_BITS_REM + L2_BITS)
#else
#define P_L1_BITS  P_L1_BITS_REM
#endif

#if V_L1_BITS_REM < 4
#define V_L1_BITS  (V_L1_BITS_REM + L2_BITS)
#else
#define V_L1_BITS  V_L1_BITS_REM
#endif

#define P_L1_SIZE  ((target_phys_addr_t)1 << P_L1_BITS)
#define V_L1_SIZE  ((target_ulong)1 << V_L1_BITS)

#define P_L1_SHIFT (TARGET_PHYS_ADDR_SPACE_BITS - TARGET_PAGE_BITS - P_L1_BITS)
#define V_L1_SHIFT (L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS - V_L1_BITS)

unsigned long qemu_real_host_page_size;
unsigned long qemu_host_page_bits;
unsigned long qemu_host_page_size;
unsigned long qemu_host_page_mask;

/* This is a multi-level map on the virtual address space.
   The bottom level has pointers to PageDesc.  */
static void *l1_map[V_L1_SIZE];

/* log support */
static const char *logfilename = 0;
FILE *logfile;
int loglevel;
static int log_append = 0;

/* statistics */
static int tb_flush_count;
static int tb_phys_invalidate_count;

#ifdef _WIN32
static void map_exec(void *addr, long size)
{
	DWORD old_protect;
	VirtualProtect(addr, size,
		       PAGE_EXECUTE_READWRITE, &old_protect);

}
#else
static void map_exec(void *addr, long size)
{
	unsigned long start, end, page_size;

	page_size = getpagesize();
	start = (unsigned long)addr;
	start &= ~(page_size - 1);

	end = (unsigned long)addr + size;
	end += page_size - 1;
	end &= ~(page_size - 1);

	mprotect((void *)start, end - start,
		 PROT_READ | PROT_WRITE | PROT_EXEC);
}
#endif

static void page_init(void)
{
	/* NOTE: we can always suppose that qemu_host_page_size >=
	   TARGET_PAGE_SIZE */
#ifdef _WIN32
	{
		SYSTEM_INFO system_info;

		GetSystemInfo(&system_info);
		qemu_real_host_page_size = system_info.dwPageSize;
	}
#else
	qemu_real_host_page_size = getpagesize();
#endif
	if (qemu_host_page_size == 0)
		qemu_host_page_size = qemu_real_host_page_size;
	if (qemu_host_page_size < TARGET_PAGE_SIZE)
		qemu_host_page_size = TARGET_PAGE_SIZE;
	qemu_host_page_bits = 0;
	while ((1 << qemu_host_page_bits) < qemu_host_page_size)
		qemu_host_page_bits++;
	qemu_host_page_mask = ~(qemu_host_page_size - 1);
}

static PageDesc *page_find_alloc(tb_page_addr_t index, int alloc)
{
	PageDesc *pd;
	void **lp;
	int i;

# define ALLOC(P, SIZE)					\
	do { P = qemu_mallocz(SIZE); } while (0)

	/* Level 1.  Always allocated.  */
	lp = l1_map + ((index >> V_L1_SHIFT) & (V_L1_SIZE - 1));

	/* Level 2..N-1.  */
	for (i = V_L1_SHIFT / L2_BITS - 1; i > 0; i--) {
		void **p = *lp;

		if (p == NULL) {
			if (!alloc) {
				return NULL;
			}
			ALLOC(p, sizeof(void *) * L2_SIZE);
			*lp = p;
		}

		lp = p + ((index >> (i * L2_BITS)) & (L2_SIZE - 1));
	}

	pd = *lp;
	if (pd == NULL) {
		if (!alloc) {
			return NULL;
		}
		ALLOC(pd, sizeof(PageDesc) * L2_SIZE);
		*lp = pd;
	}

#undef ALLOC

	return pd + (index & (L2_SIZE - 1));
}

static inline PageDesc *page_find(tb_page_addr_t index)
{
	return page_find_alloc(index, 0);
}

#if !defined(CONFIG_USER_ONLY)
#define mmap_lock() do { } while(0)
#define mmap_unlock() do { } while(0)
#endif

#define DEFAULT_CODE_GEN_BUFFER_SIZE (32 * 1024 * 1024)

static uint8_t static_code_gen_buffer[DEFAULT_CODE_GEN_BUFFER_SIZE]
__declspec_align(CODE_GEN_ALIGN);

static void code_gen_alloc(unsigned long tb_size)
{
	code_gen_buffer = static_code_gen_buffer;
	code_gen_buffer_size = DEFAULT_CODE_GEN_BUFFER_SIZE;
	map_exec(code_gen_buffer, code_gen_buffer_size);

	map_exec(code_gen_prologue, sizeof(code_gen_prologue));
	code_gen_buffer_max_size = code_gen_buffer_size -
		(TCG_MAX_OP_SIZE * OPC_BUF_SIZE);
	code_gen_max_blocks = code_gen_buffer_size / CODE_GEN_AVG_BLOCK_SIZE;
	tbs = qemu_malloc(code_gen_max_blocks * sizeof(TranslationBlock));
}

/* Must be called before using the QEMU cpus. 'tb_size' is the size
   (in bytes) allocated to the translation buffer. Zero means default
   size. */
void cpu_exec_init_all(unsigned long tb_size)
{
	cpu_gen_init();
	code_gen_alloc(tb_size);
	code_gen_ptr = code_gen_buffer;
	page_init();
	tcg_prologue_init(&tcg_ctx);
}

void cpu_exec_init(CPUState *env)
{
	QTAILQ_INIT(&env->breakpoints);
	QTAILQ_INIT(&env->watchpoints);
	env->jmp_env = &env->env_jmp_buf;
}

/* Allocate a new translation block. Flush the translation buffer if
   too many translation blocks or too much generated code. */
static TranslationBlock *tb_alloc(target_ulong pc)
{
	TranslationBlock *tb;

	if (nb_tbs >= code_gen_max_blocks ||
	    (code_gen_ptr - code_gen_buffer) >= code_gen_buffer_max_size)
		return NULL;
	tb = &tbs[nb_tbs++];
	tb->pc = pc;
	tb->cflags = 0;
	return tb;
}

void tb_free(TranslationBlock *tb)
{
	/* In practice this is mostly used for single use temporary TB
	   Ignore the hard cases and just back up if this TB happens to
	   be the last one generated.  */
	if (nb_tbs > 0 && tb == &tbs[nb_tbs - 1]) {
		code_gen_ptr = tb->tc_ptr;
		nb_tbs--;
	}
}

static inline void invalidate_page_bitmap(PageDesc *p)
{
	if (p->code_bitmap) {
		qemu_free(p->code_bitmap);
		p->code_bitmap = NULL;
	}
	p->code_write_count = 0;
}

/* Set to NULL all the 'first_tb' fields in all PageDescs. */

static void page_flush_tb_1 (int level, void **lp)
{
	int i;

	if (*lp == NULL) {
		return;
	}
	if (level == 0) {
		PageDesc *pd = *lp;
		for (i = 0; i < L2_SIZE; ++i) {
			pd[i].first_tb = NULL;
			invalidate_page_bitmap(pd + i);
		}
	} else {
		void **pp = *lp;
		for (i = 0; i < L2_SIZE; ++i) {
			page_flush_tb_1 (level - 1, pp + i);
		}
	}
}

static void page_flush_tb(void)
{
	int i;
	for (i = 0; i < V_L1_SIZE; i++) {
		page_flush_tb_1(V_L1_SHIFT / L2_BITS - 1, l1_map + i);
	}
}

/* flush all the translation blocks */
/* XXX: tb_flush is currently not thread safe */
void tb_flush(CPUState *env)
{
	if ((unsigned long)(code_gen_ptr - code_gen_buffer) > code_gen_buffer_size)
		cpu_abort(env, "Internal error: code buffer overflow\n");

	nb_tbs = 0;

	memset (env->tb_jmp_cache, 0, TB_JMP_CACHE_SIZE * sizeof (void *));
	memset (tb_phys_hash, 0, CODE_GEN_PHYS_HASH_SIZE * sizeof (void *));
	page_flush_tb();

	code_gen_ptr = code_gen_buffer;
	/* XXX: flush processor icache at this point if cache flush is
	   expensive */
	tb_flush_count++;
}

/* invalidate one TB */
static inline void tb_remove(TranslationBlock **ptb, TranslationBlock *tb,
                             int next_offset)
{
	TranslationBlock *tb1;
	for(;;) {
		tb1 = *ptb;
		if (tb1 == tb) {
			*ptb = *(TranslationBlock **)((char *)tb1 + next_offset);
			break;
		}
		ptb = (TranslationBlock **)((char *)tb1 + next_offset);
	}
}

static inline void tb_page_remove(TranslationBlock **ptb, TranslationBlock *tb)
{
	TranslationBlock *tb1;
	unsigned int n1;

	for(;;) {
		tb1 = *ptb;
		n1 = (long)tb1 & 3;
		tb1 = (TranslationBlock *)((long)tb1 & ~3);
		if (tb1 == tb) {
			*ptb = tb1->page_next[n1];
			break;
		}
		ptb = &tb1->page_next[n1];
	}
}

static inline void tb_jmp_remove(TranslationBlock *tb, int n)
{
	TranslationBlock *tb1, **ptb;
	unsigned int n1;

	ptb = &tb->jmp_next[n];
	tb1 = *ptb;
	if (tb1) {
		/* find tb(n) in circular list */
		for(;;) {
			tb1 = *ptb;
			n1 = (long)tb1 & 3;
			tb1 = (TranslationBlock *)((long)tb1 & ~3);
			if (n1 == n && tb1 == tb)
				break;
			if (n1 == 2) {
				ptb = &tb1->jmp_first;
			} else {
				ptb = &tb1->jmp_next[n1];
			}
		}
		/* now we can suppress tb(n) from the list */
		*ptb = tb->jmp_next[n];

		tb->jmp_next[n] = NULL;
	}
}

/* reset the jump entry 'n' of a TB so that it is not chained to
   another TB */
static inline void tb_reset_jump(TranslationBlock *tb, int n)
{
	tb_set_jmp_target(tb, n, (unsigned long)(tb->tc_ptr + tb->tb_next_offset[n]));
}

void tb_phys_invalidate(CPUState *env,
			TranslationBlock *tb, tb_page_addr_t page_addr)
{
	PageDesc *p;
	unsigned int h, n1;
	tb_page_addr_t phys_pc;
	TranslationBlock *tb1, *tb2;

	/* remove the TB from the hash list */
	phys_pc = tb->page_addr[0] + (tb->pc & ~TARGET_PAGE_MASK);
	h = tb_phys_hash_func(phys_pc);
	tb_remove(&tb_phys_hash[h], tb,
		  offsetof(TranslationBlock, phys_hash_next));

	/* remove the TB from the page list */
	if (tb->page_addr[0] != page_addr) {
		p = page_find(tb->page_addr[0] >> TARGET_PAGE_BITS);
		tb_page_remove(&p->first_tb, tb);
		invalidate_page_bitmap(p);
	}
	if (tb->page_addr[1] != -1 && tb->page_addr[1] != page_addr) {
		p = page_find(tb->page_addr[1] >> TARGET_PAGE_BITS);
		tb_page_remove(&p->first_tb, tb);
		invalidate_page_bitmap(p);
	}

	tb_invalidated_flag = 1;

	/* remove the TB from the hash list */
	h = tb_jmp_cache_hash_func(tb->pc);
	if (env && env->tb_jmp_cache[h] == tb)
		env->tb_jmp_cache[h] = NULL;

	/* suppress this TB from the two jump lists */
	tb_jmp_remove(tb, 0);
	tb_jmp_remove(tb, 1);

	/* suppress any remaining jumps to this TB */
	tb1 = tb->jmp_first;
	for(;;) {
		n1 = (long)tb1 & 3;
		if (n1 == 2)
			break;
		tb1 = (TranslationBlock *)((long)tb1 & ~3);
		tb2 = tb1->jmp_next[n1];
		tb_reset_jump(tb1, n1);
		tb1->jmp_next[n1] = NULL;
		tb1 = tb2;
	}
	tb->jmp_first = (TranslationBlock *)((long)tb | 2); /* fail safe */

	tb_phys_invalidate_count++;
}

static inline void set_bits(uint8_t *tab, int start, int len)
{
	int end, mask, end1;

	end = start + len;
	tab += start >> 3;
	mask = 0xff << (start & 7);
	if ((start & ~7) == (end & ~7)) {
		if (start < end) {
			mask &= ~(0xff << (end & 7));
			*tab |= mask;
		}
	} else {
		*tab++ |= mask;
		start = (start + 8) & ~7;
		end1 = end & ~7;
		while (start < end1) {
			*tab++ = 0xff;
			start += 8;
		}
		if (start < end) {
			mask = ~(0xff << (end & 7));
			*tab |= mask;
		}
	}
}

static void build_page_bitmap(PageDesc *p)
{
	int n, tb_start, tb_end;
	TranslationBlock *tb;

	p->code_bitmap = qemu_mallocz(TARGET_PAGE_SIZE / 8);

	tb = p->first_tb;
	while (tb != NULL) {
		n = (long)tb & 3;
		tb = (TranslationBlock *)((long)tb & ~3);
		/* NOTE: this is subtle as a TB may span two physical pages */
		if (n == 0) {
			/* NOTE: tb_end may be after the end of the page, but
			   it is not a problem */
			tb_start = tb->pc & ~TARGET_PAGE_MASK;
			tb_end = tb_start + tb->size;
			if (tb_end > TARGET_PAGE_SIZE)
				tb_end = TARGET_PAGE_SIZE;
		} else {
			tb_start = 0;
			tb_end = ((tb->pc + tb->size) & ~TARGET_PAGE_MASK);
		}
		set_bits(p->code_bitmap, tb_start, tb_end - tb_start);
		tb = tb->page_next[n];
	}
}

TranslationBlock *tb_gen_code(CPUState *env,
                              target_ulong pc, target_ulong cs_base,
                              int flags, int cflags)
{
	TranslationBlock *tb;
	uint8_t *tc_ptr;
	tb_page_addr_t phys_pc, phys_page2;
	target_ulong virt_page2;
	int code_gen_size;

	phys_pc = get_page_addr_code(env, pc);
	tb = tb_alloc(pc);
	if (!tb) {
		/* flush must be done */
		tb_flush(env);
		/* cannot fail at this point */
		tb = tb_alloc(pc);
		/* Don't forget to invalidate previous TB info.  */
		tb_invalidated_flag = 1;
	}
	tc_ptr = code_gen_ptr;
	tb->tc_ptr = tc_ptr;
	tb->cs_base = cs_base;
	tb->flags = flags;
	tb->cflags = cflags;
	cpu_gen_code(env, tb, &code_gen_size);
	code_gen_ptr = (void *)(((unsigned long)code_gen_ptr + code_gen_size + CODE_GEN_ALIGN - 1) & ~(CODE_GEN_ALIGN - 1));

	/* check next page if needed */
	virt_page2 = (pc + tb->size - 1) & TARGET_PAGE_MASK;
	phys_page2 = -1;
	if ((pc & TARGET_PAGE_MASK) != virt_page2) {
		phys_page2 = get_page_addr_code(env, virt_page2);
	}
	tb_link_page(tb, phys_pc, phys_page2);
	return tb;
}

/*
 * Invalidate all TBs which intersect with the target physical address range
 * [start;end[. NOTE: start and end may refer to *different* physical pages.
 * 'is_cpu_write_access' should be true if called from a real cpu write
 * access: the virtual CPU will exit the current TB if code is modified inside
 * this TB.
 */
void tb_invalidate_phys_range(CPUState *env,
			      tb_page_addr_t start, tb_page_addr_t end,
                              int is_cpu_write_access)
{
	while (start < end) {
		tb_invalidate_phys_page_range(env, start, end,
					      is_cpu_write_access);
		start &= TARGET_PAGE_MASK;
		start += TARGET_PAGE_SIZE;
	}
}

/* invalidate all TBs which intersect with the target physical page
   starting in range [start;end[. NOTE: start and end must refer to
   the same physical page. 'is_cpu_write_access' should be true if called
   from a real cpu write access: the virtual CPU will exit the current
   TB if code is modified inside this TB. */
void tb_invalidate_phys_page_range(CPUState *env,
				   tb_page_addr_t start, tb_page_addr_t end,
                                   int is_cpu_write_access)
{
	TranslationBlock *tb, *tb_next, *saved_tb;
	tb_page_addr_t tb_start, tb_end;
	PageDesc *p;
	int n;
#ifdef TARGET_HAS_PRECISE_SMC
	int current_tb_not_found = is_cpu_write_access;
	TranslationBlock *current_tb = NULL;
	int current_tb_modified = 0;
	target_ulong current_pc = 0;
	target_ulong current_cs_base = 0;
	int current_flags = 0;
#endif /* TARGET_HAS_PRECISE_SMC */

	p = page_find(start >> TARGET_PAGE_BITS);
	if (!p)
		return;
	if (!p->code_bitmap &&
	    ++p->code_write_count >= SMC_BITMAP_USE_THRESHOLD &&
	    is_cpu_write_access) {
		/* build code bitmap */
		build_page_bitmap(p);
	}

	/* we remove all the TBs in the range [start, end[ */
	/* XXX: see if in some cases it could be faster to invalidate all the code */
	tb = p->first_tb;
	while (tb != NULL) {
		n = (long)tb & 3;
		tb = (TranslationBlock *)((long)tb & ~3);
		tb_next = tb->page_next[n];
		/* NOTE: this is subtle as a TB may span two physical pages */
		if (n == 0) {
			/* NOTE: tb_end may be after the end of the page, but
			   it is not a problem */
			tb_start = tb->page_addr[0] + (tb->pc & ~TARGET_PAGE_MASK);
			tb_end = tb_start + tb->size;
		} else {
			tb_start = tb->page_addr[1];
			tb_end = tb_start + ((tb->pc + tb->size) & ~TARGET_PAGE_MASK);
		}
		if (!(tb_end <= start || tb_start >= end)) {
#ifdef TARGET_HAS_PRECISE_SMC
			if (current_tb_not_found) {
				current_tb_not_found = 0;
				current_tb = NULL;
				if (env->mem_io_pc) {
					/* now we have a real cpu fault */
					current_tb = tb_find_pc(env->mem_io_pc);
				}
			}
			if (current_tb == tb &&
			    (current_tb->cflags & CF_COUNT_MASK) != 1) {
				/* If we are modifying the current TB, we must stop
				   its execution. We could be more precise by checking
				   that the modification is after the current PC, but it
				   would require a specialized function to partially
				   restore the CPU state */

				current_tb_modified = 1;
				cpu_restore_state(current_tb, env, env->mem_io_pc);
				cpu_get_tb_cpu_state(env, &current_pc, &current_cs_base,
						     &current_flags);
			}
#endif /* TARGET_HAS_PRECISE_SMC */
			/* we need to do that to handle the case where a signal
			   occurs while doing tb_phys_invalidate() */
			saved_tb = NULL;
			if (env) {
				saved_tb = env->current_tb;
				env->current_tb = NULL;
			}
			tb_phys_invalidate(env, tb, -1);
			if (env) {
				env->current_tb = saved_tb;
				if (env->interrupt_request && env->current_tb)
					cpu_interrupt(env, env->interrupt_request);
			}
		}
		tb = tb_next;
	}
#ifdef TARGET_HAS_PRECISE_SMC
	if (current_tb_modified) {
		/* we generate a block containing just the instruction
		   modifying the memory. It will ensure that it cannot modify
		   itself */
		env->current_tb = NULL;
		tb_gen_code(env, current_pc, current_cs_base, current_flags, 1);
		cpu_resume_from_signal(env, NULL);
	}
#endif
}

/* add the tb in the target page and protect it if necessary */
static inline void tb_alloc_page(TranslationBlock *tb,
                                 unsigned int n, tb_page_addr_t page_addr)
{
	PageDesc *p;

	tb->page_addr[n] = page_addr;
	p = page_find_alloc(page_addr >> TARGET_PAGE_BITS, 1);
	tb->page_next[n] = p->first_tb;

	p->first_tb = (TranslationBlock *)((long)tb | n);
	invalidate_page_bitmap(p);
}

/* add a new TB and link it to the physical page tables. phys_page2 is
   (-1) to indicate that only one page contains the TB. */
void tb_link_page(TranslationBlock *tb,
                  tb_page_addr_t phys_pc, tb_page_addr_t phys_page2)
{
	unsigned int h;
	TranslationBlock **ptb;

	/* Grab the mmap lock to stop another thread invalidating this TB
	   before we are done.  */
	mmap_lock();
	/* add in the physical hash table */
	h = tb_phys_hash_func(phys_pc);
	ptb = &tb_phys_hash[h];
	tb->phys_hash_next = *ptb;
	*ptb = tb;

	/* add in the page list */
	tb_alloc_page(tb, 0, phys_pc & TARGET_PAGE_MASK);
	if (phys_page2 != -1)
		tb_alloc_page(tb, 1, phys_page2);
	else
		tb->page_addr[1] = -1;

	tb->jmp_first = (TranslationBlock *)((long)tb | 2);
	tb->jmp_next[0] = NULL;
	tb->jmp_next[1] = NULL;

	/* init original jump addresses */
	if (tb->tb_next_offset[0] != 0xffff)
		tb_reset_jump(tb, 0);
	if (tb->tb_next_offset[1] != 0xffff)
		tb_reset_jump(tb, 1);

	mmap_unlock();
}

/* find the TB 'tb' such that tb[0].tc_ptr <= tc_ptr <
   tb[1].tc_ptr. Return NULL if not found */
TranslationBlock *tb_find_pc(unsigned long tc_ptr)
{
	int m_min, m_max, m;
	unsigned long v;
	TranslationBlock *tb;

	if (nb_tbs <= 0)
		return NULL;
	if (tc_ptr < (unsigned long)code_gen_buffer ||
	    tc_ptr >= (unsigned long)code_gen_ptr)
		return NULL;
	/* binary search (cf Knuth) */
	m_min = 0;
	m_max = nb_tbs - 1;
	while (m_min <= m_max) {
		m = (m_min + m_max) >> 1;
		tb = &tbs[m];
		v = (unsigned long)tb->tc_ptr;
		if (v == tc_ptr)
			return tb;
		else if (tc_ptr < v) {
			m_max = m - 1;
		} else {
			m_min = m + 1;
		}
	}
	return &tbs[m_max];
}

static void tb_reset_jump_recursive(TranslationBlock *tb);

static inline void tb_reset_jump_recursive2(TranslationBlock *tb, int n)
{
	TranslationBlock *tb1, *tb_next, **ptb;
	unsigned int n1;

	tb1 = tb->jmp_next[n];
	if (tb1 != NULL) {
		/* find head of list */
		for(;;) {
			n1 = (long)tb1 & 3;
			tb1 = (TranslationBlock *)((long)tb1 & ~3);
			if (n1 == 2)
				break;
			tb1 = tb1->jmp_next[n1];
		}
		/* we are now sure now that tb jumps to tb1 */
		tb_next = tb1;

		/* remove tb from the jmp_first list */
		ptb = &tb_next->jmp_first;
		for(;;) {
			tb1 = *ptb;
			n1 = (long)tb1 & 3;
			tb1 = (TranslationBlock *)((long)tb1 & ~3);
			if (n1 == n && tb1 == tb)
				break;
			ptb = &tb1->jmp_next[n1];
		}
		*ptb = tb->jmp_next[n];
		tb->jmp_next[n] = NULL;

		/* suppress the jump to next tb in generated code */
		tb_reset_jump(tb, n);

		/* suppress jumps in the tb on which we could have jumped */
		tb_reset_jump_recursive(tb_next);
	}
}

static void tb_reset_jump_recursive(TranslationBlock *tb)
{
	tb_reset_jump_recursive2(tb, 0);
	tb_reset_jump_recursive2(tb, 1);
}

static void breakpoint_invalidate(CPUState *env, target_ulong pc)
{
	tb_invalidate_phys_page_range(env, pc, pc + 1, 0);
}

/* Add a watchpoint.  */
int cpu_watchpoint_insert(CPUState *env, target_ulong addr, target_ulong len,
                          int flags, CPUWatchpoint **watchpoint)
{
	target_ulong len_mask = ~(len - 1);
	CPUWatchpoint *wp;

	/* sanity checks: allow power-of-2 lengths, deny unaligned watchpoints */
	if ((len != 1 && len != 2 && len != 4 && len != 8) || (addr & ~len_mask)) {
		assert(0);
		return -EINVAL;
	}
	wp = qemu_malloc(sizeof(*wp));

	wp->vaddr = addr;
	wp->len_mask = len_mask;
	wp->flags = flags;

	/* keep all GDB-injected watchpoints in front */
	if (flags & BP_GDB)
		QTAILQ_INSERT_HEAD(&env->watchpoints, wp, entry);
	else
		QTAILQ_INSERT_TAIL(&env->watchpoints, wp, entry);

	if (watchpoint)
		*watchpoint = wp;
	return 0;
}

/* Remove a specific watchpoint.  */
int cpu_watchpoint_remove(CPUState *env, target_ulong addr, target_ulong len,
                          int flags)
{
	target_ulong len_mask = ~(len - 1);
	CPUWatchpoint *wp;

	QTAILQ_FOREACH(wp, &env->watchpoints, entry) {
		if (addr == wp->vaddr && len_mask == wp->len_mask
		    && flags == (wp->flags & ~BP_WATCHPOINT_HIT)) {
			cpu_watchpoint_remove_by_ref(env, wp);
			return 0;
		}
	}
	return -ENOENT;
}

/* Remove a specific watchpoint by reference.  */
void cpu_watchpoint_remove_by_ref(CPUState *env, CPUWatchpoint *watchpoint)
{
	QTAILQ_REMOVE(&env->watchpoints, watchpoint, entry);
	qemu_free(watchpoint);
}

/* Remove all matching watchpoints.  */
void cpu_watchpoint_remove_all(CPUState *env, int mask)
{
	CPUWatchpoint *wp, *next;

	QTAILQ_FOREACH_SAFE(wp, &env->watchpoints, entry, next) {
		if (wp->flags & mask)
			cpu_watchpoint_remove_by_ref(env, wp);
	}
}

/* Add a breakpoint.  */
int cpu_breakpoint_insert(CPUState *env, target_ulong pc, int flags,
                          CPUBreakpoint **breakpoint)
{
	CPUBreakpoint *bp;

	bp = qemu_malloc(sizeof(*bp));

	bp->pc = pc;
	bp->flags = flags;

	/* keep all GDB-injected breakpoints in front */
	if (flags & BP_GDB)
		QTAILQ_INSERT_HEAD(&env->breakpoints, bp, entry);
	else
		QTAILQ_INSERT_TAIL(&env->breakpoints, bp, entry);

	breakpoint_invalidate(env, pc);

	if (breakpoint)
		*breakpoint = bp;
	return 0;
}

/* Remove a specific breakpoint.  */
int cpu_breakpoint_remove(CPUState *env, target_ulong pc, int flags)
{
	CPUBreakpoint *bp;

	QTAILQ_FOREACH(bp, &env->breakpoints, entry) {
		if (bp->pc == pc && bp->flags == flags) {
			cpu_breakpoint_remove_by_ref(env, bp);
			return 0;
		}
	}
	return -ENOENT;
}

/* Remove a specific breakpoint by reference.  */
void cpu_breakpoint_remove_by_ref(CPUState *env, CPUBreakpoint *breakpoint)
{
	QTAILQ_REMOVE(&env->breakpoints, breakpoint, entry);
	breakpoint_invalidate(env, breakpoint->pc);
	qemu_free(breakpoint);
}

/* Remove all matching breakpoints. */
void cpu_breakpoint_remove_all(CPUState *env, int mask)
{
	CPUBreakpoint *bp, *next;
	QTAILQ_FOREACH_SAFE(bp, &env->breakpoints, entry, next) {
		if (bp->flags & mask)
			cpu_breakpoint_remove_by_ref(env, bp);
	}
}

/* enable or disable single step mode. EXCP_DEBUG is returned by the
   CPU loop after each instruction */
void cpu_single_step(CPUState *env, int enabled)
{
	if (env->singlestep_enabled != enabled) {
		env->singlestep_enabled = enabled;
		/* must flush all the translated code to avoid inconsistencies */
		/* XXX: only flush what is necessary */
		tb_flush(env);
	}
}

/* enable or disable low levels log */
static void cpu_set_log(int log_flags)
{
	if (!logfilename)
		return;
	loglevel = log_flags;
	if (loglevel && !logfile) {
		logfile = fopen(logfilename, log_append ? "a" : "w");
		if (!logfile) {
			perror(logfilename);
			_exit(1);
		}
		log_append = 1;
	}
	if (!loglevel && logfile) {
		fclose(logfile);
		logfile = NULL;
	}
}

void cpu_set_log_filename(const char *filename)
{
	logfilename = strdup(filename);
	if (logfile) {
		fclose(logfile);
		logfile = NULL;
	}
	cpu_set_log(loglevel);
}

static void cpu_unlink_tb(CPUState *env)
{
	/* FIXME: TB unchaining isn't SMP safe.  For now just ignore the
	   problem and hope the cpu will stop of its own accord.  For userspace
	   emulation this often isn't actually as bad as it sounds.  Often
	   signals are used primarily to interrupt blocking syscalls.  */
	TranslationBlock *tb;
	static spinlock_t interrupt_lock = SPIN_LOCK_UNLOCKED;

	spin_lock(&interrupt_lock);
	tb = env->current_tb;
	/* if the cpu is currently executing code, we must unlink it and
	   all the potentially executing TB */
	if (tb) {
		env->current_tb = NULL;
		tb_reset_jump_recursive(tb);
	}
	spin_unlock(&interrupt_lock);
}

void cpu_interrupt(CPUState *env, int mask)
{
	env->interrupt_request |= mask;
	cpu_unlink_tb(env);
}

void cpu_reset_interrupt(CPUState *env, int mask)
{
	env->interrupt_request &= ~mask;
}

void cpu_exit(CPUState *env)
{
	env->exit_request = 1;
	cpu_unlink_tb(env);
}
