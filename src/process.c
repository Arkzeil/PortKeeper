#include "portkeeper.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int pk_proc_open(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld", (long)pid);
    return open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
}

static ssize_t read_proc(int procfd, const char *name, char *buffer, size_t size)
{
    int fd = openat(procfd, name, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t count;
    do {
        count = read(fd, buffer, size - 1);
    } while (count < 0 && errno == EINTR && !pk_interrupted);
    int saved = errno;
    close(fd);
    errno = saved;
    if (count >= 0)
        buffer[count] = '\0';
    return count;
}

int pk_owns_socket(int procfd, int fd, uint64_t inode)
{
    char path[64], actual[128], expected[128];
    snprintf(path, sizeof(path), "fd/%d", fd);
    ssize_t count = readlinkat(procfd, path, actual, sizeof(actual) - 1);
    if (count < 0)
        return -1;
    actual[count] = '\0';
    snprintf(expected, sizeof(expected), "socket:[%" PRIu64 "]", inode);
    if (strcmp(actual, expected) != 0) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

void pk_describe(pk_row *row)
{
    strcpy(row->command, "<unavailable>");
    if (!row->pid)
        return;
    int procfd = pk_proc_open(row->pid);
    if (procfd < 0 || pk_owns_socket(procfd, row->fd, row->inode) < 0) {
        if (procfd >= 0)
            close(procfd);
        row->pid = 0;
        row->fd = -1;
        return;
    }
    ssize_t count = read_proc(procfd, "comm", row->command, sizeof(row->command));
    if (count < 0)
        strcpy(row->command, "<unavailable>");
    else {
        if (count > 0 && row->command[count - 1] == '\n')
            row->command[count - 1] = '\0';
        pk_sanitize(row->command);
    }
    close(procfd);
}

int pk_command_line(pid_t pid, char *buffer, size_t size)
{
    int procfd = pk_proc_open(pid);
    if (procfd < 0)
        return -1;
    ssize_t count = read_proc(procfd, "cmdline", buffer, size);
    int saved = errno;
    close(procfd);
    errno = saved;
    if (count < 0)
        return -1;
    for (ssize_t i = 0; i < count; ++i)
        if (buffer[i] == '\0')
            buffer[i] = ' ';
    while (count > 0 && buffer[count - 1] == ' ')
        buffer[--count] = '\0';
    pk_sanitize(buffer);
    return 0;
}

static int start_time(int procfd, uint64_t *value)
{
    char buffer[4096];
    if (read_proc(procfd, "stat", buffer, sizeof(buffer)) < 0)
        return -1;
    /* comm may contain spaces and ')'. The final ')' ends field 2. */
    char *end_comm = strrchr(buffer, ')');
    if (!end_comm) {
        errno = EPROTO;
        return -1;
    }
    char *save = NULL;
    char *token = strtok_r(end_comm + 1, " ", &save);
    for (int field = 3; field < 22 && token; ++field)
        token = strtok_r(NULL, " ", &save);
    if (!token || *token < '0' || *token > '9') {
        errno = EPROTO;
        return -1;
    }
    errno = 0;
    char *tail;
    unsigned long long parsed = strtoull(token, &tail, 10);
    if (errno || *tail) {
        errno = EPROTO;
        return -1;
    }
    *value = (uint64_t)parsed;
    return 0;
}

int pk_target_signal(const pk_target *target, int signal_number)
{
#ifdef SYS_pidfd_send_signal
    return (int)syscall(SYS_pidfd_send_signal, target->pidfd, signal_number, NULL, 0);
#else
    (void)target;
    (void)signal_number;
    errno = ENOSYS;
    return -1;
#endif
}

void pk_target_close(pk_target *target)
{
    if (target->pidfd >= 0)
        close(target->pidfd);
    if (target->procfd >= 0)
        close(target->procfd);
    target->pidfd = target->procfd = -1;
}

int pk_target_open(pid_t pid, pk_target *target)
{
    *target = (pk_target){.pid = pid, .procfd = -1, .pidfd = -1};
    if (pid <= 1 || pid == getpid()) {
        errno = EPERM;
        return -1;
    }
    target->procfd = pk_proc_open(pid);
    if (target->procfd < 0)
        return -1;
    uint64_t before, after;
    if (start_time(target->procfd, &before) < 0)
        goto fail;
#ifdef SYS_pidfd_open
    target->pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
#else
    errno = ENOSYS;
#endif
    if (target->pidfd < 0)
        goto fail;
    /* The original proc directory must still be live AFTER pidfd_open.
     * It never retargets a recycled PID. This binds both handles to one task. */
    if (start_time(target->procfd, &after) < 0)
        goto fail;
    if (before != after) {
        errno = ESTALE;
        goto fail;
    }
    if (pk_target_signal(target, 0) < 0)
        goto fail;
    return 0;
fail: {
        int saved = errno;
        pk_target_close(target);
        errno = saved;
        return -1;
    }
}
