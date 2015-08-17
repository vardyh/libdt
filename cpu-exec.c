/*
 *  i386 emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
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

#include "cpu.h"
#include "tcg.h"
#include "qemu-barrier.h"

int tb_invalidated_flag;

void cpu_loop_exit(CPUState *env)
{
	env->current_tb = NULL;
	longjmp(*env->jmp_env, 1);
}

/* exit the current TB from a signal handler. The host registers are
   restored in a state compatible with the CPU emulator
*/
void cpu_resume_from_signal(CPUState *env, void *puc)
{
	/* XXX: restore cpu registers saved in host registers */

	env->exception_index = -1;
	longjmp(*env->jmp_env, 1);
}

/* Execute the code without caching the generated code. An interpreter
   could be used if available. */
static void cpu_exec_nocache(CPUState *env, int max_cycles,
                             TranslationBlock *orig_tb)
{
	unsigned long next_tb;
	TranslationBlock *tb;

	/* Should never happen.
	   We only end up here when an existing TB is too long.  */
	if (max_cycles > CF_COUNT_MASK)
		max_cycles = CF_COUNT_MASK;

	tb = tb_gen_code(env, orig_tb->pc, orig_tb->cs_base, orig_tb->flags,
			 max_cycles);
	env->current_tb = tb;
	/* execute the generated code */
	next_tb = tcg_qemu_tb_exec(env, tb->tc_ptr);
	env->current_tb = NULL;

	if ((next_tb & 3) == 2) {
		/* Restore PC.  This may happen if async event occurs before
		   the TB starts executing.  */
		cpu_pc_from_tb(env, tb);
	}
	tb_phys_invalidate(env, tb, -1);
	tb_free(tb);
}

static TranslationBlock *tb_find_slow(CPUState *env,
                                      target_ulong pc,
                                      target_ulong cs_base,
                                      uint64_t flags)
{
	TranslationBlock *tb, **ptb1;
	unsigned int h;
	tb_page_addr_t phys_pc, phys_page1, phys_page2;
	target_ulong virt_page2;

	tb_invalidated_flag = 0;

	/* find translated block using physical mappings */
	phys_pc = get_page_addr_code(env, pc);
	phys_page1 = phys_pc & TARGET_PAGE_MASK;
	phys_page2 = -1;
	h = tb_phys_hash_func(phys_pc);
	ptb1 = &tb_phys_hash[h];
	for(;;) {
		tb = *ptb1;
		if (!tb)
			goto not_found;
		if (tb->pc == pc &&
		    tb->page_addr[0] == phys_page1 &&
		    tb->cs_base == cs_base &&
		    tb->flags == flags) {
			/* check next page if needed */
			if (tb->page_addr[1] != -1) {
				virt_page2 = (pc & TARGET_PAGE_MASK) +
					TARGET_PAGE_SIZE;
				phys_page2 = get_page_addr_code(env, virt_page2);
				if (tb->page_addr[1] == phys_page2)
					goto found;
			} else {
				goto found;
			}
		}
		ptb1 = &tb->phys_hash_next;
	}
not_found:
	/* if no translated code available, then translate it now */
	tb = tb_gen_code(env, pc, cs_base, flags, 0);

found:
	/* Move the last found TB to the head of the list */
	if (likely(*ptb1)) {
		*ptb1 = tb->phys_hash_next;
		tb->phys_hash_next = tb_phys_hash[h];
		tb_phys_hash[h] = tb;
	}
	/* we add the TB in the virtual pc hash table */
	env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
	return tb;
}

static inline TranslationBlock *tb_find_fast(CPUState *env)
{
	TranslationBlock *tb;
	target_ulong cs_base, pc;
	int flags;

	/* we record a subset of the CPU state. It will
	   always be the same before a given translated block
	   is executed. */
	cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
	tb = env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
	if (unlikely(!tb || tb->pc != pc || tb->cs_base != cs_base ||
		     tb->flags != flags)) {
		tb = tb_find_slow(env, pc, cs_base, flags);
	}
	return tb;
}

static CPUDebugExcpHandler *debug_excp_handler;

CPUDebugExcpHandler *cpu_set_debug_excp_handler(CPUDebugExcpHandler *handler)
{
	CPUDebugExcpHandler *old_handler = debug_excp_handler;
	debug_excp_handler = handler;
	return old_handler;
}

static void cpu_handle_debug_exception(CPUState *env)
{
	CPUWatchpoint *wp;

	if (!env->watchpoint_hit) {
		QTAILQ_FOREACH(wp, &env->watchpoints, entry) {
			wp->flags &= ~BP_WATCHPOINT_HIT;
		}
	}
	if (debug_excp_handler) {
		debug_excp_handler(env);
	}
}

/* main execution loop */
int cpu_exec(CPUState *env)
{
	int ret, interrupt_request;
	TranslationBlock *tb;
	uint8_t *tc_ptr;
	unsigned long next_tb;

	if (env->halted) {
		if (!cpu_has_work(env))
			return EXCP_HALTED;
		env->halted = 0;
	}

	cpu_single_env = env;

	/* put eflags in CPU temporary format */
	CC_SRC = env->eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
	DF = 1 - (2 * ((env->eflags >> 10) & 1));
	CC_OP = CC_OP_EFLAGS;
	env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);

	env->exception_index = -1;

	/* prepare setjmp context for exception handling */
	for(;;) {
		if (setjmp(*env->jmp_env) == 0) {
			/* if an exception is pending, we execute it here */
			if (env->exception_index >= 0) {
				if (env->exception_index >= EXCP_INTERRUPT) {
					/* exit request from the cpu execution loop */
					ret = env->exception_index;
					if (ret == EXCP_DEBUG) {
						cpu_handle_debug_exception(env);
					}
					break;
				} else {
					ret = env->exception_index;
					break;
				}
			}

			next_tb = 0; /* force lookup of first TB */
			for(;;) {
				interrupt_request = env->interrupt_request;
				if (unlikely(interrupt_request)) {
					if (unlikely(env->singlestep_enabled & SSTEP_NOIRQ)) {
						/* Mask out external interrupts for this step. */
						interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
					}
					if (interrupt_request & CPU_INTERRUPT_DEBUG) {
						env->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
						env->exception_index = EXCP_DEBUG;
						cpu_loop_exit(env);
					}
					/* Don't use the cached interrupt_request value,
					   do_interrupt may have updated the EXITTB flag. */
					if (env->interrupt_request & CPU_INTERRUPT_EXITTB) {
						env->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
						/* ensure that no TB jump will be modified as
						   the program flow was changed */
						next_tb = 0;
					}
				}
				if (unlikely(env->exit_request)) {
					env->exit_request = 0;
					env->exception_index = EXCP_INTERRUPT;
					cpu_loop_exit(env);
				}

				spin_lock(&tb_lock);
				tb = tb_find_fast(env);
				/* Note: we do it here to avoid a gcc bug on Mac OS X when
				   doing it in tb_find_slow */
				if (tb_invalidated_flag) {
					/* as some TB could have been invalidated because
					   of memory exceptions while generating the code, we
					   must recompute the hash index here */
					next_tb = 0;
					tb_invalidated_flag = 0;
				}

				/* see if we can patch the calling TB. When the TB
				   spans two pages, we cannot safely do a direct
				   jump. */
				if (next_tb != 0 && tb->page_addr[1] == -1) {
					tb_add_jump((TranslationBlock *)(next_tb & ~3), next_tb & 3, tb);
				}
				spin_unlock(&tb_lock);

				/* cpu_interrupt might be called while translating the
				   TB, but before it is linked into a potentially
				   infinite loop and becomes env->current_tb. Avoid
				   starting execution if there is a pending interrupt. */
				env->current_tb = tb;
				barrier();
				if (likely(!env->exit_request)) {
					tc_ptr = tb->tc_ptr;
					/* execute the generated code */
					next_tb = tcg_qemu_tb_exec(env, tc_ptr);
					if ((next_tb & 3) == 2) {
						/* Instruction counter expired.  */
						int insns_left;
						tb = (TranslationBlock *)(long)(next_tb & ~3);
						/* Restore PC.  */
						cpu_pc_from_tb(env, tb);
						insns_left = env->icount_decr.u32;
						if (env->icount_extra && insns_left >= 0) {
							/* Refill decrementer and continue execution.  */
							env->icount_extra += insns_left;
							if (env->icount_extra > 0xffff) {
								insns_left = 0xffff;
							} else {
								insns_left = env->icount_extra;
							}
							env->icount_extra -= insns_left;
							env->icount_decr.u16.low = insns_left;
						} else {
							if (insns_left > 0) {
								/* Execute remaining instructions.  */
								cpu_exec_nocache(env, insns_left, tb);
							}
							env->exception_index = EXCP_INTERRUPT;
							next_tb = 0;
							cpu_loop_exit(env);
						}
					}
				}
				env->current_tb = NULL;
				/* reset soft MMU for next block (it can currently
				   only be set by a memory fault) */
			} /* for(;;) */
		} else {
			/* Reload env after longjmp - the compiler may have smashed all
			 * local variables as longjmp is marked 'noreturn'. */
			env = cpu_single_env;
		}
	} /* for(;;) */

	/* restore flags in standard format */
	env->eflags = env->eflags | cpu_cc_compute_all(env, CC_OP)
		| (DF & DF_MASK);

	/* fail safe : never use cpu_single_env outside cpu_exec() */
	cpu_single_env = NULL;
	return ret;
}
