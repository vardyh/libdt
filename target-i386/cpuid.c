/*
 *  i386 CPUID helper functions
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cpu.h"

// FIXME: cpuid may be disabled in Ring3
void host_cpuid(uint32_t function, uint32_t count,
                uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    uint32_t vec[4];

#ifdef __x86_64__
    asm volatile("cpuid"
                 : "=a"(vec[0]), "=b"(vec[1]),
                   "=c"(vec[2]), "=d"(vec[3])
                 : "0"(function), "c"(count) : "cc");
#else
    asm volatile("pusha \n\t"
                 "cpuid \n\t"
                 "mov %%eax, 0(%2) \n\t"
                 "mov %%ebx, 4(%2) \n\t"
                 "mov %%ecx, 8(%2) \n\t"
                 "mov %%edx, 12(%2) \n\t"
                 "popa"
                 : : "a"(function), "c"(count), "S"(vec)
                 : "memory", "cc");
#endif

    if (eax)
        *eax = vec[0];
    if (ebx)
        *ebx = vec[1];
    if (ecx)
        *ecx = vec[2];
    if (edx)
        *edx = vec[3];
}

typedef struct x86_def_t {
    struct x86_def_t *next;
    uint32_t level;
    uint32_t vendor1, vendor2, vendor3;
    int family;
    int model;
    int stepping;
    uint32_t features, ext_features, ext2_features, ext3_features;
    uint32_t xlevel;
    char model_id[48];
    int vendor_override;
    uint32_t flags;
    /* Store the results of Centaur's CPUID instructions */
    uint32_t ext4_features;
    uint32_t xlevel2;
} x86_def_t;

#define I486_FEATURES (CPUID_FP87 | CPUID_VME | CPUID_PSE)
#define PENTIUM_FEATURES (I486_FEATURES | CPUID_DE | CPUID_TSC | \
          CPUID_MSR | CPUID_MCE | CPUID_CX8 | CPUID_MMX | CPUID_APIC)
#define PENTIUM2_FEATURES (PENTIUM_FEATURES | CPUID_PAE | CPUID_SEP | \
          CPUID_MTRR | CPUID_PGE | CPUID_MCA | CPUID_CMOV | CPUID_PAT | \
          CPUID_PSE36 | CPUID_FXSR)
#define PENTIUM3_FEATURES (PENTIUM2_FEATURES | CPUID_SSE)
#define PPRO_FEATURES (CPUID_FP87 | CPUID_DE | CPUID_PSE | CPUID_TSC | \
          CPUID_MSR | CPUID_MCE | CPUID_CX8 | CPUID_PGE | CPUID_CMOV | \
          CPUID_PAT | CPUID_FXSR | CPUID_MMX | CPUID_SSE | CPUID_SSE2 | \
          CPUID_PAE | CPUID_SEP | CPUID_APIC)
#define EXT2_FEATURE_MASK 0x0183F3FF

#define TCG_FEATURES (CPUID_FP87 | CPUID_PSE | CPUID_TSC | CPUID_MSR | \
          CPUID_PAE | CPUID_MCE | CPUID_CX8 | CPUID_APIC | CPUID_SEP | \
          CPUID_MTRR | CPUID_PGE | CPUID_MCA | CPUID_CMOV | CPUID_PAT | \
          CPUID_PSE36 | CPUID_CLFLUSH | CPUID_ACPI | CPUID_MMX | \
          CPUID_FXSR | CPUID_SSE | CPUID_SSE2 | CPUID_SS)
          /* partly implemented:
          CPUID_MTRR, CPUID_MCA, CPUID_CLFLUSH (needed for Win64)
          CPUID_PSE36 (needed for Solaris) */
          /* missing:
          CPUID_VME, CPUID_DTS, CPUID_SS, CPUID_HT, CPUID_TM, CPUID_PBE */
#define TCG_EXT_FEATURES (CPUID_EXT_SSE3 | CPUID_EXT_MONITOR | \
          CPUID_EXT_CX16 | CPUID_EXT_POPCNT | \
          CPUID_EXT_HYPERVISOR)
          /* missing:
          CPUID_EXT_DTES64, CPUID_EXT_DSCPL, CPUID_EXT_VMX, CPUID_EXT_EST,
          CPUID_EXT_TM2, CPUID_EXT_XTPR, CPUID_EXT_PDCM, CPUID_EXT_XSAVE */
#define TCG_EXT2_FEATURES ((TCG_FEATURES & EXT2_FEATURE_MASK) | \
          CPUID_EXT2_NX | CPUID_EXT2_MMXEXT | CPUID_EXT2_RDTSCP | \
          CPUID_EXT2_3DNOW | CPUID_EXT2_3DNOWEXT)
          /* missing:
          CPUID_EXT2_PDPE1GB */
#define TCG_EXT3_FEATURES (CPUID_EXT3_LAHF_LM | CPUID_EXT3_SVM | \
          CPUID_EXT3_CR8LEG | CPUID_EXT3_ABM | CPUID_EXT3_SSE4A)
#define TCG_SVM_FEATURES 0

static int cpu_x86_fill_model_id(char *str)
{
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    int i;

    for (i = 0; i < 3; i++) {
        host_cpuid(0x80000002 + i, 0, &eax, &ebx, &ecx, &edx);
        memcpy(str + i * 16 +  0, &eax, 4);
        memcpy(str + i * 16 +  4, &ebx, 4);
        memcpy(str + i * 16 +  8, &ecx, 4);
        memcpy(str + i * 16 + 12, &edx, 4);
    }
    return 0;
}

static int cpu_x86_fill_host(x86_def_t *x86_cpu_def)
{
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

    host_cpuid(0x0, 0, &eax, &ebx, &ecx, &edx);
    x86_cpu_def->level = eax;
    x86_cpu_def->vendor1 = ebx;
    x86_cpu_def->vendor2 = edx;
    x86_cpu_def->vendor3 = ecx;

    host_cpuid(0x1, 0, &eax, &ebx, &ecx, &edx);
    x86_cpu_def->family = ((eax >> 8) & 0x0F) + ((eax >> 20) & 0xFF);
    x86_cpu_def->model = ((eax >> 4) & 0x0F) | ((eax & 0xF0000) >> 12);
    x86_cpu_def->stepping = eax & 0x0F;
    x86_cpu_def->ext_features = ecx;
    x86_cpu_def->features = edx;

    host_cpuid(0x80000000, 0, &eax, &ebx, &ecx, &edx);
    x86_cpu_def->xlevel = eax;

    host_cpuid(0x80000001, 0, &eax, &ebx, &ecx, &edx);
    x86_cpu_def->ext2_features = edx;
    x86_cpu_def->ext3_features = ecx;
    cpu_x86_fill_model_id(x86_cpu_def->model_id);
    x86_cpu_def->vendor_override = 0;

    /* Call Centaur's CPUID instruction. */
    if (x86_cpu_def->vendor1 == CPUID_VENDOR_VIA_1 &&
        x86_cpu_def->vendor2 == CPUID_VENDOR_VIA_2 &&
        x86_cpu_def->vendor3 == CPUID_VENDOR_VIA_3) {
        host_cpuid(0xC0000000, 0, &eax, &ebx, &ecx, &edx);
        if (eax >= 0xC0000001) {
            /* Support VIA max extended level */
            x86_cpu_def->xlevel2 = eax;
            host_cpuid(0xC0000001, 0, &eax, &ebx, &ecx, &edx);
            x86_cpu_def->ext4_features = edx;
        }
    }

    return 0;
}

static int cpu_x86_find_by_name(x86_def_t *x86_cpu_def)
{
    cpu_x86_fill_host(x86_cpu_def);
    return 0;
}

int cpu_x86_register (CPUX86State *env)
{
    x86_def_t def1, *def = &def1;

    memset(def, 0, sizeof(*def));

    if (cpu_x86_find_by_name(def) < 0)
        return -1;
    if (def->vendor1) {
        env->cpuid_vendor1 = def->vendor1;
        env->cpuid_vendor2 = def->vendor2;
        env->cpuid_vendor3 = def->vendor3;
    } else {
        env->cpuid_vendor1 = CPUID_VENDOR_INTEL_1;
        env->cpuid_vendor2 = CPUID_VENDOR_INTEL_2;
        env->cpuid_vendor3 = CPUID_VENDOR_INTEL_3;
    }
    env->cpuid_level = def->level;
    if (def->family > 0x0f)
        env->cpuid_version = 0xf00 | ((def->family - 0x0f) << 20);
    else
        env->cpuid_version = def->family << 8;
    env->cpuid_version |= ((def->model & 0xf) << 4) | ((def->model >> 4) << 16);
    env->cpuid_version |= def->stepping;
    env->cpuid_features = def->features;
    env->cpuid_ext_features = def->ext_features;
    env->cpuid_ext2_features = def->ext2_features;
    env->cpuid_ext3_features = def->ext3_features;
    env->cpuid_xlevel = def->xlevel;
    env->cpuid_ext4_features = def->ext4_features;
    env->cpuid_xlevel2 = def->xlevel2;
    env->cpuid_features &= TCG_FEATURES;
    env->cpuid_ext_features &= TCG_EXT_FEATURES;
    env->cpuid_ext2_features &= (TCG_EXT2_FEATURES
#ifdef TARGET_X86_64
	 | CPUID_EXT2_SYSCALL | CPUID_EXT2_LM
#endif
         );
    env->cpuid_ext3_features &= TCG_EXT3_FEATURES;
    {
        const char *model_id = def->model_id;
        int c, len, i;
        if (!model_id)
            model_id = "";
        len = strlen(model_id);
        for(i = 0; i < 48; i++) {
            if (i >= len)
                c = '\0';
            else
                c = (uint8_t)model_id[i];
            env->cpuid_model[i >> 2] |= c << (8 * (i & 3));
        }
    }
    return 0;
}

static void get_cpuid_vendor(CPUX86State *env, uint32_t *ebx,
                             uint32_t *ecx, uint32_t *edx)
{
    *ebx = env->cpuid_vendor1;
    *edx = env->cpuid_vendor2;
    *ecx = env->cpuid_vendor3;

    /* sysenter isn't supported on compatibility mode on AMD, syscall
     * isn't supported in compatibility mode on Intel.
     * Normally we advertise the actual cpu vendor, but you can override
     * this if you want to use KVM's sysenter/syscall emulation
     * in compatibility mode and when doing cross vendor migration
     */
    host_cpuid(0, 0, NULL, ebx, ecx, edx);
}

void cpu_x86_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
                   uint32_t *eax, uint32_t *ebx,
                   uint32_t *ecx, uint32_t *edx)
{
    /* test if maximum index reached */
    if (index & 0x80000000) {
        if (index > env->cpuid_xlevel) {
            if (env->cpuid_xlevel2 > 0) {
                /* Handle the Centaur's CPUID instruction. */
                if (index > env->cpuid_xlevel2) {
                    index = env->cpuid_xlevel2;
                } else if (index < 0xC0000000) {
                    index = env->cpuid_xlevel;
                }
            } else {
                index =  env->cpuid_xlevel;
            }
        }
    } else {
        if (index > env->cpuid_level)
            index = env->cpuid_level;
    }

    switch(index) {
    case 0:
        *eax = env->cpuid_level;
        get_cpuid_vendor(env, ebx, ecx, edx);
        break;
    case 1:
        *eax = env->cpuid_version;
        *ebx = (env->cpuid_apic_id << 24) | 8 << 8; /* CLFLUSH size in quad words, Linux wants it. */
        *ecx = env->cpuid_ext_features;
        *edx = env->cpuid_features;
        if (env->nr_cores * env->nr_threads > 1) {
            *ebx |= (env->nr_cores * env->nr_threads) << 16;
            *edx |= 1 << 28;    /* HTT bit */
        }
        break;
    case 2:
        /* cache info: needed for Pentium Pro compatibility */
        *eax = 1;
        *ebx = 0;
        *ecx = 0;
        *edx = 0x2c307d;
        break;
    case 4:
        /* cache info: needed for Core compatibility */
        if (env->nr_cores > 1) {
            *eax = (env->nr_cores - 1) << 26;
        } else {
            *eax = 0;
        }
        switch (count) {
            case 0: /* L1 dcache info */
                *eax |= 0x0000121;
                *ebx = 0x1c0003f;
                *ecx = 0x000003f;
                *edx = 0x0000001;
                break;
            case 1: /* L1 icache info */
                *eax |= 0x0000122;
                *ebx = 0x1c0003f;
                *ecx = 0x000003f;
                *edx = 0x0000001;
                break;
            case 2: /* L2 cache info */
                *eax |= 0x0000143;
                if (env->nr_threads > 1) {
                    *eax |= (env->nr_threads - 1) << 14;
                }
                *ebx = 0x3c0003f;
                *ecx = 0x0000fff;
                *edx = 0x0000001;
                break;
            default: /* end of info */
                *eax = 0;
                *ebx = 0;
                *ecx = 0;
                *edx = 0;
                break;
        }
        break;
    case 5:
        /* mwait info: needed for Core compatibility */
        *eax = 0; /* Smallest monitor-line size in bytes */
        *ebx = 0; /* Largest monitor-line size in bytes */
        *ecx = CPUID_MWAIT_EMX | CPUID_MWAIT_IBE;
        *edx = 0;
        break;
    case 6:
        /* Thermal and Power Leaf */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 7:
        *eax = 0;
	*ebx = 0;
	*ecx = 0;
	*edx = 0;
        break;
    case 9:
        /* Direct Cache Access Information Leaf */
        *eax = 0; /* Bits 0-31 in DCA_CAP MSR */
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xA:
        /* Architectural Performance Monitoring Leaf */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xD:
        /* Processor Extended State */
        if (!(env->cpuid_ext_features & CPUID_EXT_XSAVE)) {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
            break;
        }
        *eax = 0;
	*ebx = 0;
	*ecx = 0;
	*edx = 0;
        break;
    case 0x80000000:
        *eax = env->cpuid_xlevel;
        *ebx = env->cpuid_vendor1;
        *edx = env->cpuid_vendor2;
        *ecx = env->cpuid_vendor3;
        break;
    case 0x80000001:
        *eax = env->cpuid_version;
        *ebx = 0;
        *ecx = env->cpuid_ext3_features;
        *edx = env->cpuid_ext2_features;

        /* The Linux kernel checks for the CMPLegacy bit and
         * discards multiple thread information if it is set.
         * So dont set it here for Intel to make Linux guests happy.
         */
        if (env->nr_cores * env->nr_threads > 1) {
            uint32_t tebx, tecx, tedx;
            get_cpuid_vendor(env, &tebx, &tecx, &tedx);
            if (tebx != CPUID_VENDOR_INTEL_1 ||
                tedx != CPUID_VENDOR_INTEL_2 ||
                tecx != CPUID_VENDOR_INTEL_3) {
                *ecx |= 1 << 1;    /* CmpLegacy bit */
            }
        }
        break;
    case 0x80000002:
    case 0x80000003:
    case 0x80000004:
        *eax = env->cpuid_model[(index - 0x80000002) * 4 + 0];
        *ebx = env->cpuid_model[(index - 0x80000002) * 4 + 1];
        *ecx = env->cpuid_model[(index - 0x80000002) * 4 + 2];
        *edx = env->cpuid_model[(index - 0x80000002) * 4 + 3];
        break;
    case 0x80000005:
        /* cache info (L1 cache) */
        *eax = 0x01ff01ff;
        *ebx = 0x01ff01ff;
        *ecx = 0x40020140;
        *edx = 0x40020140;
        break;
    case 0x80000006:
        /* cache info (L2 cache) */
        *eax = 0;
        *ebx = 0x42004200;
        *ecx = 0x02008140;
        *edx = 0;
        break;
    case 0x80000008:
        /* virtual & phys address size in low 2 bytes. */
/* XXX: This value must match the one used in the MMU code. */
        if (env->cpuid_ext2_features & CPUID_EXT2_LM) {
            /* 64 bit processor */
/* XXX: The physical address space is limited to 42 bits in exec.c. */
            *eax = 0x00003028;	/* 48 bits virtual, 40 bits physical */
        } else {
            if (env->cpuid_features & CPUID_PSE36)
                *eax = 0x00000024; /* 36 bits physical */
            else
                *eax = 0x00000020; /* 32 bits physical */
        }
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (env->nr_cores * env->nr_threads > 1) {
            *ecx |= (env->nr_cores * env->nr_threads) - 1;
        }
        break;
    case 0x8000000A:
	if (env->cpuid_ext3_features & CPUID_EXT3_SVM) {
		*eax = 0x00000001; /* SVM Revision */
		*ebx = 0x00000010; /* nr of ASIDs */
		*ecx = 0;
		*edx = 0;
	} else {
		*eax = 0;
		*ebx = 0;
		*ecx = 0;
		*edx = 0;
	}
        break;
    case 0xC0000000:
        *eax = env->cpuid_xlevel2;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xC0000001:
        /* Support for VIA CPU's CPUID instruction */
        *eax = env->cpuid_version;
        *ebx = 0;
        *ecx = 0;
        *edx = env->cpuid_ext4_features;
        break;
    case 0xC0000002:
    case 0xC0000003:
    case 0xC0000004:
        /* Reserved for the future, and now filled with zero */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    default:
        /* reserved values: zero */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    }
}
