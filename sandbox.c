#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "sandbox.h"

/*
#define Scratch "/home/ori/www/eigenstate.org/sandbox-scratch"
#define Template "/home/ori/www/eigenstate/sandbox/template"
*/
#define Scratch "/home/ori/src/myr/sandbox/"
#define Template "/test-template"
int urandom;

void failure(char *msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    printf("\terr: %s\n", strerror(errno));
    exit(1);
}

void message(char *msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
}

/* generates an exclusively opened directory
 * as a subdirectory of 'base', returning
 * the FD.
 */
int tempdir(char *base, char *buf, size_t nbuf)
{
    size_t n;
    uint64_t r[4];

    read(urandom, r, sizeof r);
    n = snprintf(buf, nbuf, "%s/%016lx%016lx%016lx%016lx", base, r[0], r[1], r[2], r[3]);
    /* we expect a length of base + 16 chars of random  + slash */
    if (n != 64 + 1 + strlen(base))
        failure("Could not create scratch directory: %s (len=%d)\n", buf, n);
    if (mkdir(buf, 0700) == -1)
        failure("Could not create scratch directory %s\n", buf);
    printf("Created directory: %s\n", buf);
    return open(buf, O_DIRECTORY | O_RDONLY);
}

char *buildfiles[] = {
    /* binaries */
    "myrbuild",
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
    "lib/myr/std",
    "lib/myr/libstd.a",
    "lib/myr/regex",
    "lib/myr/libregex.a",
    "lib/myr/bio",
    "lib/myr/libbio.a",
    "lib/myr/date",
    "lib/myr/libdate.a",
    "lib/myr/_myrrt.o",
    NULL
};

void setupcompile(char *tmppath, size_t npath, int *compiledir)
{
    int tmpdir, bindir;
    char **p;

    tmpdir = tempdir("/build", tmppath, npath);
    if (tmpdir == -1)
        failure("Could not create scratch directory\n");
    if (mkdirat(tmpdir, "lib64", 0700) == -1)
        failure("Could not create lib64 directory\n");
    if (mkdirat(tmpdir, "lib", 0700) == -1)
        failure("Could not create lib directory\n");
    if (mkdirat(tmpdir, "lib/myr", 0700) == -1)
        failure("Could not create lib/myr directory\n");
    if (mkdirat(tmpdir, "tmp", 0700) == -1)
        failure("Could not create tmp directory\n");
    bindir = open(Template, O_RDONLY);
    if (bindir == -1)
        failure("Could not find binaries\n");

    for (p = buildfiles; *p; p++)
        if (linkat(bindir, *p, tmpdir, *p, 0) == -1)
            failure("Could not initialize scratch directory: %s\n", *p);
    *compiledir = tmpdir;
}

void setuprun(char *tmppath, size_t npath, int compiledir, int *rundir)
{
    int tmpdir;

    tmpdir = tempdir("/run", tmppath, npath);
    if (tmpdir == -1)
        failure("Could not create scratch directory\n");
    *rundir = tmpdir;
}

/*
  chroots into the scratch directory, filtersas many of the
  syscalls as it can, and sets some fairly strict ulimit values.
 */
void dropaccess()
{
}

void readpost(int dir)
{
    int fd;
    static const char output[] =
        "use std\nconst main = {; std.put(\"hello world!\\n\")}\n";

    fd = openat(dir, "in.myr", O_WRONLY | O_CREAT, 0600);
    if (fd == -1)
        failure("Could not read post data\n");
    if (write(fd, output, strlen(output)) != strlen(output))
        failure("Could not write post data to disk\n");
    close(fd);
}

void run(char *dir, char **cmd, void *filter)
{
    int pid, status, st;
    char *env[] = {"LD_LIBRARY_PATH=/lib64", "PATH=/", NULL};

    pid = fork();
    if (pid == -1) {
        failure("Could not fork\n");
    } else if (pid == 0) {
        if (chdir(dir) == -1)
            failure("Unable to dir\n");
        if (chroot(dir) == -1)
            failure("Unable to chroot\n");
        if (execve(cmd[0], cmd, env) == -1)
            failure("Unable to exec");
    } else {
        st = waitpid(pid, &status, 0);
        if (st == -1)
            message("Failed to wait for PID %d\n", pid);
        if (WIFEXITED(status))
            message("%s: exited with status %d\n", cmd[0], WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            message("%s: exited with signal %d\n", cmd[0], WTERMSIG(status));
        else
            message("%s: exited witout signal or status\n", cmd[0]);
    }
}

void runsession()
{
    /* compile commands */
    char *compilecmd[] = {"myrbuild", "in.myr", "-I", "/lib/myr", "-r", "/lib/myr/_myrrt.o", NULL};
    char *runcmd[] = {"/a.out", NULL};
    /* run commands */
    char compilepath[1024], runpath[1024];
    int compiledir, rundir;

    if (chdir(Scratch) == -1)
        failure("Could not chdir\n");
    if (chroot(Scratch) == -1)
        failure("Could not chroot\n");
    setupcompile(compilepath, sizeof compilepath, &compiledir);
    readpost(compiledir);
    setuprun(runpath, sizeof runpath, compiledir, &rundir);
    run(compilepath, compilecmd, compilefilter);
    if (linkat(compiledir, "a.out", rundir, "a.out", 0) == -1)
        failure("Could not access compiled output");
    run(runpath, runcmd, runfilter);
}

#define KiB 1024
#define MiB 1024*KiB

void limit()
{
    if (setrlimit(RLIMIT_AS, &(struct rlimit){.rlim_cur=512*MiB, .rlim_max=512*MiB}) == -1)
        failure("Could not limit address space\n");
    if (setrlimit(RLIMIT_CPU, &(struct rlimit){.rlim_cur=1, .rlim_max=1}) == -1)
        failure("Could not limit u\n");
    /*
    if (setrlimit(RLIMIT_NPROC, &(struct rlimit){.rlim_cur=256, .rlim_max=256}) == -1)
        failure("Could not limit nproc\n");
    */
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
}

int main(int argc, char **argv)
{
    int pid;
    int status, st;

    /* set things up for killing */
    urandom = open("/dev/urandom", O_RDONLY);
    if (urandom == -1)
        failure("Could not open /dev/urandom");
    limit();
    pid = fork();
    if (pid == -1) {
        failure("Could not fork");
    } else if (pid == 0) {
        if (setsid() == -1)
            failure("Could not set session id\n");
        runsession();
    } else {
        usleep(500*1000); /* 500 ms for the command to run */
        st = waitpid(pid, &status, WNOHANG);
        if (st == 0 && kill(-pid, 9) == -1) {
            failure("Could not kill sid %d\n", pid);
        } else {
            if (WIFEXITED(status))
                message("sandbox exited with status %d\n", WEXITSTATUS(status));
            else if (WIFSIGNALED(status))
                message("sandbox exited with signal %d\n", WTERMSIG(status));
            else
                message("sandbox exited witout signal or status\n");
        }
    }
    return 0;
}
