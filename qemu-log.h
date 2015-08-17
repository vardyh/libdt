#ifndef QEMU_LOG_H
#define QEMU_LOG_H

/* The deprecated global variables: */
extern FILE *logfile;
extern int loglevel;


/*
 * The new API:
 *
 */

/* Log settings checking macros: */

/* Returns true if qemu_log() will really write somewhere
 */
#define qemu_log_enabled() (logfile != NULL)

/* Returns true if a bit is set in the current loglevel mask
 */
#define qemu_loglevel_mask(b) ((loglevel & (b)) != 0)


/* Logging functions: */

#ifdef NDEBUG

# define qemu_log(...) do {} while (0)
# define qemu_log_vprintf(...) do {} while (0)
# define qemu_log_mask(...) do {} while (0)

#else

/* main logging function
 */
# define qemu_log(...) do {					\
		if (logfile)					\
			fprintf(logfile, ## __VA_ARGS__);	\
	} while (0)

/* vfprintf-like logging function
 */
# define qemu_log_vprintf(fmt, va) do {			\
		if (logfile)				\
			vfprintf(logfile, fmt, va);	\
	} while (0)

/* log only if a bit is set on the current loglevel mask
 */
# define qemu_log_mask(b, ...) do {				\
		if (loglevel & (b))				\
			fprintf(logfile, ## __VA_ARGS__);	\
	} while (0)

#endif

/* page_dump() output to the log file: */
#define log_page_dump() page_dump(logfile)

/* Close the log file */
#define qemu_log_close() do { \
        fclose(logfile);      \
        logfile = NULL;       \
    } while (0)

/* Set up a new log file */
#define qemu_log_set_file(f) do { \
        logfile = (f);            \
    } while (0)

/* Set up a new log file, only if none is set */
#define qemu_log_try_set_file(f) do { \
        if (!logfile)                 \
            logfile = (f);            \
    } while (0)

void cpu_set_log_filename(const char *filename);

#endif
