# sandbox

_(If you're looking for the container-based sandboxing environment for Cloudflare Workers, please refer to https://github.com/cloudflare/sandbox-sdk)_

## Linux seccomp made easy

This package provides a simple way to enable basic `seccomp` [system call filtering][1] in any application (even proprietary one) via environment variables. It is very similar to `SystemCallFilter=` [functionality in systemd][2], but with some advantages:

  * it doesn't have some of `systemd` limitations:
    > the execve, exit, exit_group, getrlimit, rt_sigreturn, sigreturn system calls and the system calls for querying time and sleeping are implicitly whitelisted...
  * it can provide tighter filtering for dynamically linked binaries

### Building

The build system expects a recent version of [libseccomp][5] to be available as a static library. It is recommended to build it from upstream source rather than rely on the version from a particular distribution.

The `Makefile` will look for a valid [libseccomp][5] tree and the build in the `libseccomp` directory, so the easiest way to satisfy the dependency is to do the following in the project directory:

```bash
user@dev:~/sandbox$ curl -L -O https://github.com/seccomp/libseccomp/releases/download/v2.4.3/libseccomp-2.4.3.tar.gz
user@dev:~/sandbox$ tar xf libseccomp-2.4.3.tar.gz && mv libseccomp-2.4.3 libseccomp
user@dev:~/sandbox$ cd libseccomp && ./configure --enable-shared=no && make
```

Then build `sandbox` with `make` from the project directory:

```bash
user@dev:~/sandbox$ make
cc -c -fPIC -Ilibseccomp/include -o sandbox.o sandbox.c
cc -c -fPIC -Ilibseccomp/include -o preload.o preload.c
cc -shared -Wl,--version-script=libsandbox.version -o libsandbox.so sandbox.o preload.o libseccomp/src/.libs/libseccomp.a
cc -c -fPIC -Ilibseccomp/include -o sandboxify.o sandboxify.c
cc -o sandboxify sandboxify.o sandbox.o libseccomp/src/.libs/libseccomp.a
```

### Usage

The package provides a dynamically linked library `libsandbox.so` for dynamically linked executables and a command line utility `sandboxify` for statically linked executables. The system call filter can be defined with the following environment variables:

  * if `SECCOMP_SYSCALL_ALLOW` is defined, all system calls listed in the list will be allowed; if the process will attempt to call any system call not from the list, it will be killed by the operating system
    * example: `SECCOMP_SYSCALL_ALLOW="open:write"`
  * otherwise, if `SECCOMP_SYSCALL_DENY` is defined, all system calls listed in the list attempted to be used by the process, will cause the process to be killed; all other system calls are allowed
    * example: `SECCOMP_SYSCALL_DENY="execve:mprotect"`

#### Dynamically linked executables

For dynamically linked executables the sandboxing code is injected using the `LD_PRELOAD` [dynamic linker option][3].

No sandboxing:

```bash
$ ./helloworld
Hello, world!
```

With sandboxing:

```bash
$ LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libsandbox.so SECCOMP_SYSCALL_ALLOW="fstat:write:exit_group" ./helloworld
adding fstat to the process seccomp filter
adding write to the process seccomp filter
adding exit_group to the process seccomp filter
Hello, world!
```

If the process uses a system call, which was not explicitly listed:

```bash
$ LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libsandbox.so SECCOMP_SYSCALL_ALLOW="fstat:exit_group" ./helloworld
adding fstat to the process seccomp filter
adding exit_group to the process seccomp filter
Bad system call
```

and a audit event is generated:

```
[Mon Apr  6 11:27:30 2020] audit: type=1326 audit(1586168850.755:5): auid=1000 uid=1000 gid=1000 ses=2 subj=kernel pid=3148 comm="helloworld" exe="/home/ignat/git/sandbox/helloworld" sig=31 arch=c000003e syscall=1 compat=0 ip=0x7f6c3650e504 code=0x80000000
```

##### Make it permanent

It is possible to permanently link the executable to `libsandbox.so` without recompiling the code and avoid defining `LD_PRELOAD` environment variable. For example:

Before:

```bash
$ ldd ./helloworld
	linux-vdso.so.1 (0x00007ffd2018e000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8392ee9000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f83930bd000)
```

Adding `libsandbox.so` as a runtime dependency:

```bash
$ patchelf --add-needed /usr/lib/x86_64-linux-gnu/libsandbox.so ./helloworld
$ ldd ./helloworld
	linux-vdso.so.1 (0x00007fffb74cf000)
	/usr/lib/x86_64-linux-gnu/libsandbox.so (0x00007f3706499000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f37062cc000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f37064ee000)
$ SECCOMP_SYSCALL_ALLOW="fstat:write:exit_group" ./helloworld
adding fstat to the process seccomp filter
adding write to the process seccomp filter
adding exit_group to the process seccomp filter
Hello, world!
```

#### Statically linked executables

For statically linked executables the sandboxing code is injected by launching the application with `sandboxify` command line utility.

```bash
$ SECCOMP_SYSCALL_ALLOW="brk:arch_prctl:uname:readlink:fstat:write:exit_group" sandboxify ./helloworld
adding brk to the process seccomp filter
adding arch_prctl to the process seccomp filter
adding uname to the process seccomp filter
adding readlink to the process seccomp filter
adding fstat to the process seccomp filter
adding write to the process seccomp filter
adding exit_group to the process seccomp filter
Hello, world!
```

Under the hood `sandboxify` uses [`PTRACE_O_SUSPEND_SECCOMP` ptrace option][7], therefore requires `CAP_SYS_ADMIN` capability to operate properly. Depending on the target system [Yama LSM][8] configuration `sandboxify` might also require `CAP_SYS_PTRACE` capability.

#### permissive (log) mode

When sandboxing new applications it is usually not very clear what system calls it uses to define the proper seccomp filter, so on initial stages it is possible to configure the sandbox to log filter violations instead of immediately killing the process via `SECCOMP_DEFAULT_ACTION=log` environment variable.

```bash
$ LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libsandbox.so SECCOMP_SYSCALL_ALLOW="" SECCOMP_DEFAULT_ACTION=log ./helloworld
Hello, world!
```

Above filter does not allow any system call for the `helloworld` application, but logs the violations instead of killing the process. The violations can be monitored via `dmesg` or auditd (if running on the system):

```
[Mon Apr  6 12:04:02 2020] audit: type=1326 audit(1586171042.680:138): auid=1000 uid=1000 gid=1000 ses=2 subj=kernel pid=3284 comm="helloworld" exe="/home/ignat/git/sandbox/helloworld" sig=0 arch=c000003e syscall=5 compat=0 ip=0x7f21a2d42af3 code=0x7ffc0000
[Mon Apr  6 12:04:02 2020] audit: type=1326 audit(1586171042.680:139): auid=1000 uid=1000 gid=1000 ses=2 subj=kernel pid=3284 comm="helloworld" exe="/home/ignat/git/sandbox/helloworld" sig=0 arch=c000003e syscall=1 compat=0 ip=0x7f21a2d43504 code=0x7ffc0000
[Mon Apr  6 12:04:02 2020] audit: type=1326 audit(1586171042.680:140): auid=1000 uid=1000 gid=1000 ses=2 subj=kernel pid=3284 comm="helloworld" exe="/home/ignat/git/sandbox/helloworld" sig=0 arch=c000003e syscall=231 compat=0 ip=0x7f21a2d1f9d6 code=0x7ffc0000
```

The example above shows `helloworld` binary tried to use system calls `5`, `1` and `231`. By searching online, for example [here][4]: it is possible to translate the numbers into system call names: `fstat`, `write` and `exit_group` respectively.

#### sandboxify vs libsandbox.so

While it is possible to use `sandboxify` utility for dynamically linked executables as well, `libsandbox.so` has the advantage of being executed later in the process startup, usually after all runtime framework initialisation has been completed. This results in a much tighter seccomp filter, as explicitly allowing system calls, which are used only during process startup, is not required.

For example, if we attempt to use `sandboxify` to secure dynamically linked `helloworld` application from above, instead of `SECCOMP_SYSCALL_ALLOW="fstat:write:exit_group"` we would need `SECCOMP_SYSCALL_ALLOW="brk:access:openat:fstat:mmap:close:read:mprotect:munmap:arch_prctl:write:exit_group"` to allow all the system calls the dynamic linker and the C-runtime need to setup the process.

#### Check the status

It is possible to use [`/proc/[pid]/status`][6] to verify the target process has a seccomp policy applied by checking the `Seccomp` field in the output (it has to be set to `2`):

```bash
$ grep Seccomp /proc/self/status
Seccomp:	0
$ LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libsandbox.so SECCOMP_SYSCALL_ALLOW="brk:close:exit_group:fstat:futex:mmap:openat:read:rt_sigaction:sigaltstack:stat:write" SECCOMP_DEFAULT_ACTION=log grep Seccomp /proc/self/status
adding brk to the process seccomp filter
adding close to the process seccomp filter
adding exit_group to the process seccomp filter
adding fstat to the process seccomp filter
adding futex to the process seccomp filter
adding mmap to the process seccomp filter
adding openat to the process seccomp filter
adding read to the process seccomp filter
adding rt_sigaction to the process seccomp filter
adding sigaltstack to the process seccomp filter
adding stat to the process seccomp filter
adding write to the process seccomp filter
Seccomp:	2
```

Unfortunately, the field only indicates that some policy was applied, but provides no further details.

### Currently not supported

  * filters based on specific system call arguments
  * custom return error codes

[1]: http://man7.org/linux/man-pages/man2/seccomp.2.html
[2]: https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=
[3]: http://man7.org/linux/man-pages/man8/ld.so.8.html
[4]: https://filippo.io/linux-syscall-table/
[5]: https://github.com/seccomp/libseccomp
[6]: https://man7.org/linux/man-pages/man5/proc.5.html
[7]: https://man7.org/linux/man-pages/man2/ptrace.2.html
[8]: https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html
