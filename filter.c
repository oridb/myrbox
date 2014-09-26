#include <stdlib.h>
#include <stddef.h>

#include <sys/prctl.h>
#include <sys/syscall.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#define Allow(syscall) \
    	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##syscall, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

static struct sock_filter masterfilter[] = {
    /* validate arch */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

    /* load syscall */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

    /* list of allowed syscalls */
    Allow(access),
    Allow(arch_prctl),
    Allow(prctl),
    Allow(brk),
    Allow(chdir),
    Allow(chmod),
    Allow(chroot),
    Allow(clone),
    Allow(close),
    Allow(dup2),
    Allow(execve),
    Allow(exit),
    Allow(exit_group),
    Allow(fcntl),
    Allow(fork),
    Allow(fstat),
    Allow(fsync),
    Allow(getcwd),
    Allow(getpid),
    Allow(getrlimit),
    Allow(getrusage),
    Allow(gettid),
    Allow(kill),
    Allow(linkat),
    Allow(lseek),
    Allow(lstat),
    Allow(mkdir),
    Allow(mkdirat),
    Allow(mmap),
    Allow(mprotect),
    Allow(munmap),
    Allow(nanosleep),
    Allow(open),
    Allow(openat),
    Allow(read),
    Allow(restart_syscall),
    Allow(rt_sigprocmask),
    Allow(setsid),
    Allow(stat),
    Allow(tgkill),
    Allow(umask),
    Allow(uname),
    Allow(wait4),
    Allow(write),

    /* and if we don't match above, die */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog masterprog = {
    .len = sizeof(masterfilter)/sizeof(masterfilter[0]),
    .filter = masterfilter
};

struct sock_filter compilefilter[] = {
    /* validate arch */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

    /* load syscall */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

    /* list of allowed syscalls */
    Allow(access),
    Allow(arch_prctl),
    Allow(prctl),
    Allow(brk),
    Allow(chdir),
    Allow(chmod),
    Allow(clone),
    Allow(close),
    Allow(dup2),
    Allow(execve),
    Allow(exit),
    Allow(exit_group),
    Allow(fcntl),
    Allow(fork),
    Allow(fstat),
    Allow(fsync),
    Allow(getcwd),
    Allow(getpid),
    Allow(getrlimit),
    Allow(getrusage),
    Allow(gettid),
    Allow(linkat),
    Allow(lseek),
    Allow(lstat),
    Allow(mmap),
    Allow(mprotect),
    Allow(munmap),
    Allow(nanosleep),
    Allow(open),
    Allow(openat),
    Allow(read),
    Allow(restart_syscall),
    Allow(rt_sigprocmask),
    Allow(setsid),
    Allow(stat),
    Allow(tgkill),
    Allow(umask),
    Allow(uname),
    Allow(wait4),
    Allow(write),

    /* and if we don't match above, die */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog compileprog = {
    .len = sizeof(compilefilter)/sizeof(compilefilter[0]),
    .filter = compilefilter
};

struct sock_filter runfilter[] = {
    /* validate arch */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

    /* load syscall */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

    /* list of allowed syscalls */
    Allow(execve),
    Allow(exit),
    Allow(exit_group),
    Allow(mmap),
    Allow(munmap),
    Allow(write),

    /* and if we don't match above, die */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
};
struct sock_fprog runprog = {
    .len = sizeof(runfilter)/sizeof(runfilter[0]),
    .filter = runfilter
};

