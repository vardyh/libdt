#include <stdlib.h>
#include <string.h>

#include <vxeng.h>
#include "cpu.h"

struct vxeng_dt {
	struct vxeng;
	CPUX86State *env;
};

static int EXPORT_DECL libdt_exec(struct vxeng *_e,
				  struct x86_env *env, int flags)
{
	struct vxeng_dt *e = (void *) _e;
	if (!e || !env)
		return -1;
	// TODO:
	memcpy(e->env, env, sizeof (*env));
	return cpu_x86_exec(e->env);
}

static void EXPORT_DECL libdt_free(struct vxeng *_e)
{
	struct vxeng_dt *e = (void *) _e;
	if (e->env)
		cpu_x86_close(e->env);
	free(e);
}

static struct vxeng * EXPORT_DECL libdt_alloc(void)
{
	struct vxeng_dt *e;

	e = malloc(sizeof (*e));
	if (!e)
		return 0;

	e->env = cpu_init();
	if (!e->env) {
		free(e);
		return 0;
	}
	cpu_reset(e->env);

	e->env->opaque = e;

	e->env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
#ifdef TARGET_X86_64
	e->env->hflags |= HF_PE_MASK | HF_CS64_MASK | HF_SS64_MASK;
#else
	e->env->hflags |= HF_PE_MASK | HF_CS32_MASK | HF_SS32_MASK;
#endif

	e->free = libdt_free;
	e->exec = libdt_exec;

	return (void *) e;
}

static struct vxeng_class vxeng_libdt = {
#ifdef TARGET_X86_64
	"dt64",
#else
	"dt32",
#endif
	libdt_alloc,
};

__constructor__(libdt_init)
{
	cpu_exec_init_all(0);
	vxeng_register(&vxeng_libdt);
}
