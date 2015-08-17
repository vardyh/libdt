#ifndef QEMU_COMMON_H
#define QEMU_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
#include "qemu-os-win32.h"
#else
#include "qemu-os-posix.h"
#endif

/* cutils.c */
void pstrcpy(char *buf, int buf_size, const char *str);
char *pstrcat(char *buf, int buf_size, const char *s);

void *qemu_malloc(size_t size);
void *qemu_mallocz(size_t size);
void qemu_free(void *ptr);

void cpu_exec_init_all(unsigned long tb_size);

#define qemu_init_vcpu(env) do { } while (0)

#endif
