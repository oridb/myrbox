#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ftw.h>
#include <sched.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/capability.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#include "sandbox.h"
#include "config.h"

#define KiB (1024)
#define MiB (1024*KiB)
#define Maxsize 16*KiB

int urandom;          /* fd for /dev/urandom */
char buildpath[1024];
int builddir;
char runpath[1024];
int rundir;

void failure(char *msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    fprintf(stdout, "Internal error: ");
    vfprintf(stdout, msg, ap);
    va_end(ap);

    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    fprintf(stderr, "\terr: %s\n", strerror(errno));
    va_end(ap);

    fflush(stdout);
    fflush(stderr);
    exit(1);
}

/*
 * Waitpid will wait for any state change. We only
 * want the state changes where a process exits.
 */
int waitexit(pid_t pid, int *status, int flags)
{
    int st;

    do {
        st = waitpid(pid, status, flags);
        if (flags & WNOHANG)
            return st;
    } while (!WIFEXITED(*status) && !WIFSIGNALED(*status));
    if (WIFEXITED(*status) || WIFSIGNALED(*status))
        return st;
    return -1;
}

void message(char *msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    vfprintf(stdout, msg, ap);
    fflush(stdout);
    fflush(stderr);
    va_end(ap);
}

int tempname(char *buf, size_t nbuf, char *base)
{
    uint64_t r[4];
    size_t n;

    read(urandom, r, sizeof r);
    n = snprintf(buf, nbuf, "%s%016"PRIx64"%016"PRIx64"%016"PRIx64"%016"PRIx64"",
                 base, r[0], r[1], r[2], r[3]);
    /* we expect a length of base + 64 chars of random  */
    if (n != 64 + strlen(base))
        failure("Could not create filename\n", buf, n);
    return 0;
}

/*
 * generates an exclusively opened directory
 * as a subdirectory of 'base', returning
 * the FD.
 */
int tempdir(char *base, char *buf, size_t nbuf)
{
    if (tempname(buf, nbuf, base) == -1)
        failure("Could not generate temporary name\n");
    if (mkdir(buf, 0700) == -1)
        failure("Could not create scratch directory %s\n", buf);
    return open(buf, O_DIRECTORY | O_RDONLY);
}

/*
 * The files needed for building. This is very system specific, unfortunately.
 * The libraries can be determined by 'ldd'ing the required executables.
 */
char *buildfiles[] = {
    /* binaries */
    "mbld",
    "6m",
    "as",
    "ld",
    /* libraries */
    "lib64/libbfd-2.24.51-system.20140903.so",
    "lib64/libopcodes-2.24.51-system.20140903.so",
    "lib64/libz.so.1",
    "lib64/libdl.so.2",
    "lib64/libc.so.6",
    "lib64/ld-linux-x86-64.so.2",
    "lib/myr/sys",
    "lib/myr/libsys.a",
    "lib/myr/std",
    "lib/myr/libstd.a",
    "lib/myr/regex",
    "lib/myr/libregex.a",
    "lib/myr/bio",
    "lib/myr/libbio.a",
    "lib/myr/cryptohash",
    "lib/myr/libcryptohash.a",
    "lib/myr/date",
    "lib/myr/libdate.a",
    "lib/myr/_myrrt.o",
    NULL
};

void setupcompile()
{
    int tmpldir;
    char **p;

    if (mkdirat(builddir, "lib64", 0700) == -1)
        failure("Could not create lib64 directory\n");
    if (mkdirat(builddir, "lib", 0700) == -1)
        failure("Could not create lib directory\n");
    if (mkdirat(builddir, "lib/myr", 0700) == -1)
        failure("Could not create lib/myr directory\n");
    if (mkdirat(builddir, "tmp", 0700) == -1)
        failure("Could not create tmp directory\n");
    tmpldir = open(Template, O_RDONLY);
    if (tmpldir == -1)
        failure("Could not find binaries\n");

    for (p = buildfiles; *p; p++)
        if (linkat(tmpldir, *p, builddir, *p, 0) == -1)
            failure("Could not initialize scratch directory copy of '%s'\n", *p);
}

void writeall(int fd, char *buf, ssize_t nread)
{
    ssize_t n, nwritten;

    nwritten = 0;
    while (nwritten < nread) {
        n = write(fd, buf + nwritten, nread - nwritten);
        if (n < 0)
            failure("failed to write POST data\n");
        else if (n == 0)
            break;
        else
            nwritten += n;
    }
    if (nwritten != nread)
        failure("failed to write POST data\n");
}

void readpost(int dir)
{
    int fd;
    char buf[Maxsize];
    ssize_t n, nread;

    fd = openat(dir, "in.myr", O_WRONLY | O_CREAT, 0600);
    if (fd == -1)
        failure("Could not read post data\n");
    nread = 0;
    while (nread < Maxsize) {
        n = read(0, buf, Maxsize - nread);
        if (n < 0)
            failure("Failed to read POST data\n");
        else if (n == 0)
            break;
        else
            nread += n;
    }
    writeall(fd, buf, nread);
    close(fd);
}

void run(char *dir, char **cmd, struct sock_fprog *filter, int catchstderr)
{
    int pid, status, st;
    char *env[] = {"LD_LIBRARY_PATH=/lib64", "PATH=/", NULL};

    pid = fork();
    if (pid == -1) {
        failure("Could not fork\n");
    } else if (pid == 0) {
        if (catchstderr && dup2(1, 2) == -1)
            failure("Unable to capture stderr\n");
        if (chdir(dir) == -1)
            failure("Unable to dir\n");
        if (chroot(dir) == -1)
            failure("Unable to chroot\n");
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, filter) == -1)
            failure("Could not start seccomp");
        if (execve(cmd[0], cmd, env) == -1)
            failure("Unable to exec");
    } else {
        st = waitexit(pid, &status, 0);
        if (st == 0)
            failure("We should only get status==0 with WNOHANG");
        else if (st == -1)
            failure("Failed to wait for PID %d\n", pid);
        else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
            failure("%s: exited with status %d\n", cmd[0], WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            failure("%s: exited with signal %d\n", cmd[0], WTERMSIG(status));
    }
}

int runsession(void *p)
{
    /* compile commands */
    char *buildcmd[] = {"mbld", "-b", "a.out", "in.myr", "-I", "/lib/myr", "-r", "/lib/myr/_myrrt.o", NULL};
    char *runcmd[] = {"/a.out", NULL};
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data;

    /* more priv drops */
    capget(&hdr, &data);
    data.effective = 0;
    data.permitted = 0;
    capset(&hdr, &data);
    /* run commands */
    setupcompile();
    readpost(builddir);
    run(buildpath, buildcmd, &compileprog, 1);
    if (linkat(builddir, "a.out", rundir, "a.out", 0) == -1) {
        message("Could not access compiled output");
        failure("Could not access compiled output");
    }
    run(runpath, runcmd, &runprog, 1);
    return 0;
}

/* sets up resource limits and chroots */
void limit()
{
    if (setrlimit(RLIMIT_NPROC, &(struct rlimit){.rlim_cur=2048, .rlim_max=2048}) == -1)
        failure("Could not limit nproc\n");
    if (setrlimit(RLIMIT_AS, &(struct rlimit){.rlim_cur=512*MiB, .rlim_max=512*MiB}) == -1)
        failure("Could not limit address space\n");
    if (setrlimit(RLIMIT_CPU, &(struct rlimit){.rlim_cur=1, .rlim_max=1}) == -1)
        failure("Could not limit u\n");
    if (setrlimit(RLIMIT_CORE, &(struct rlimit){.rlim_cur=0, .rlim_max=0}) == -1)
        failure("Could not limit core\n");
    if (setrlimit(RLIMIT_FSIZE, &(struct rlimit){.rlim_cur=32*MiB, .rlim_max=32*MiB}) == -1)
        failure("Could not limit fsize\n");
    if (setrlimit(RLIMIT_NOFILE, &(struct rlimit){.rlim_cur=32, .rlim_max=32}) == -1)
        failure("Could not limit files\n");
    if (setrlimit(RLIMIT_RSS, &(struct rlimit){.rlim_cur=128*MiB, .rlim_max=128*MiB}) == -1)
        failure("Could not limit rss\n");
    if (setrlimit(RLIMIT_STACK, &(struct rlimit){.rlim_cur=32*MiB, .rlim_max=32*MiB}) == -1)
        failure("Could not limit stack\n");
    if (chdir(Scratch) == -1)
        failure("Could not chdir %s\n", Scratch);
    if (chroot(Scratch) == -1)
        failure("Could not chroot\n");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
        failure("Could not prevent new privs");
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &masterprog) == -1)
        failure("Could not start seccomp");
}

int deleteent(const char *fpath, const struct stat *sb, int typeflag, struct FTW* ftwbuf)
{
    /* we should try to keep going */
    if (remove(fpath) == -1)
        fprintf(stderr, "Could not remove %s\n", fpath);
    return 0;
}

int main(int argc, char **argv)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data;
    void *mem;
    char logname[1024];
    int status, st, linkst;
    int logdir;
    int pid;

    /* /dev/urandom can't be opened after we chroot */
    urandom = open("/dev/urandom", O_RDONLY);
    if (urandom == -1)
        failure("Could not open /dev/urandom");

    limit();

    printf("Content-type: text/plain\r\n\r\n");
    /*
     * creates scratch directories: this needs to be done in the
     * watchdog for reliable cleanup.
     */
    printf("Building\n");
    fflush(stdout);
    fflush(stderr);
    builddir = tempdir("/build/", buildpath, sizeof buildpath);
    if (builddir == -1)
        failure("Could not create scratch directory\n");
    rundir = tempdir("/run/", runpath, sizeof runpath);
    if (rundir == -1)
        failure("Could not create scratch directory\n");
    logdir = open("/log", O_RDONLY); 
    if (logdir == -1)
        failure("Could not open log dir\n");
    if (tempname(logname, sizeof logname, "in.myr.") == -1)
        failure("Could not generate log file name");

    /* and start up the process that does actual work */
    mem = malloc(4*1024*1024);
    if (!mem)
        failure("Could not allocate child stack");
    pid = clone(runsession, mem, CLONE_NEWPID, NULL);
    if (pid == -1) {
        failure("Could not start subprocess\n");
    } else {
        /* more priv drops */
        capget(&hdr, &data);
        data.effective = 0;
        data.permitted = 0;
        capset(&hdr, &data);

        /* watchdog */
        usleep(500*1000); /* 500 ms for the command to run */
        status = 0;
        st = waitexit(pid, &status, WNOHANG);
        if (st == 0) {
            message("Invocation timed out\n");
            if (kill(-pid, 9) == -1) 
                failure("Could not kill sid %d\n", pid);
        } else if (st != 1) {
            if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
                message("exited with status %d\n", WEXITSTATUS(status));
            else if (WIFSIGNALED(status))
                message("exited with signal %d\n", WTERMSIG(status));
        } else {
            failure("failed to wait for PID %d\n", pid);
        }
        linkst = linkat(builddir, "in.myr", logdir, logname, 0);
        nftw(buildpath, deleteent, FTW_DEPTH, 512);
        nftw(runpath, deleteent, FTW_DEPTH, 512);
        if (linkst == -1)
            failure("Could not link logfile\n");
    }
    return 0;
}
