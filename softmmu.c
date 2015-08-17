#include <vxeng.h>
#include "cpu.h"
#include "exec.h"

__INLINE__
void raise_mmfault(CPUX86State *env, target_ulong addr, uint32_t err)
{
	env->cr[2] = addr;
	raise_exception_env(env, EXCP0E_PAGE, err);
}

uint8_t REGPARM __ldb_mmu(target_ulong addr, int mmu_idx)
{
	CPUX86State *env = cpu_single_env;
	uint8_t val;
	struct vxeng *e = (void *) env->opaque;
	if (e->callouts.vmread(e, addr, &val, sizeof (val)) <= 0)
		raise_mmfault(env, addr, (mmu_idx < 0) ? 0x10 : 0x00);
	return val;
}

void REGPARM __stb_mmu(target_ulong addr, uint8_t val, int mmu_idx)
{
	CPUX86State *env = cpu_single_env;
	struct vxeng *e = (void *) env->opaque;
	if (e->callouts.vmwrite(e, addr, &val, sizeof (val)) <= 0)
		raise_mmfault(env, addr, 2);
	tb_invalidate_phys_range((void *) e, addr, addr + 1, 0);
}

uint16_t REGPARM __ldw_mmu(target_ulong addr, int mmu_idx)
{
	int rc;
	CPUX86State *env = cpu_single_env;
	uint16_t val;
	struct vxeng *e = (void *) env->opaque;
	rc = e->callouts.vmread(e, addr, &val, sizeof (val));
	if (rc == 2)
		return val;
	if (rc <= 0)
		raise_mmfault(env, addr, (mmu_idx < 0) ? 0x10 : 0x00);
	raise_mmfault(env, addr + 1, (mmu_idx < 0) ? 0x10 : 0x00);
	/* never comes here */
	return 0;
}

void REGPARM __stw_mmu(target_ulong addr, uint16_t val, int mmu_idx)
{
	int rc;
	CPUX86State *env = cpu_single_env;
	struct vxeng *e = (void *) env->opaque;
	rc = e->callouts.vmwrite(e, addr, &val, sizeof (val));
	if (rc < 0)
		rc = 0;
	if (rc > 0)
		tb_invalidate_phys_range((void *) e, addr, addr + rc, 0);
	if (rc != 2)
		raise_mmfault(env, addr + rc, 2);
}

uint32_t REGPARM __ldl_mmu(target_ulong addr, int mmu_idx)
{
	int rc;
	CPUX86State *env = cpu_single_env;
	uint32_t val;
	struct vxeng *e = (void *) env->opaque;
	rc = e->callouts.vmread(e, addr, &val, sizeof (val));
	if (rc == 4)
		return val;
	if (rc < 0)
		rc = 0;
	raise_mmfault(env, addr + rc, (mmu_idx < 0) ? 0x10 : 0x00);
	/* never comes here */
	return 0;
}

void REGPARM __stl_mmu(target_ulong addr, uint32_t val, int mmu_idx)
{
	int rc;
	CPUX86State *env = cpu_single_env;
	struct vxeng *e = (void *) env->opaque;
	rc = e->callouts.vmwrite(e, addr, &val, sizeof (val));
	if (rc < 0)
		rc = 0;
	if (rc > 0)
		tb_invalidate_phys_range((void *) e, addr, addr + rc, 0);
	if (rc != 4)
		raise_mmfault(env, addr + rc, 2);
}

uint64_t REGPARM __ldq_mmu(target_ulong addr, int mmu_idx)
{
	int rc;
	CPUX86State *env = cpu_single_env;
	uint64_t val;
	struct vxeng *e = (void *) env->opaque;
	rc = e->callouts.vmread(e, addr, &val, sizeof (val));
	if (rc == 8)
		return val;
	if (rc < 0)
		rc = 0;
	raise_mmfault(env, addr + rc, (mmu_idx < 0) ? 0x10 : 0x00);
	/* never comes here */
	return 0;
}

void REGPARM __stq_mmu(target_ulong addr, uint64_t val, int mmu_idx)
{
	int rc;
	CPUX86State *env = cpu_single_env;
	struct vxeng *e = (void *) env->opaque;
	rc = e->callouts.vmwrite(e, addr, &val, sizeof (val));
	if (rc < 0)
		rc = 0;
	if (rc > 0)
		tb_invalidate_phys_range((void *) e, addr, addr + rc, 0);
	if (rc != 4)
		raise_mmfault(env, addr + rc, 2);
}
