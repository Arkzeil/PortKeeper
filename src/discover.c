#include "portkeeper.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

volatile sig_atomic_t pk_interrupted;

static int compare(const void *left, const void *right)
{
    const pk_row *a = left, *b = right;
    if (a->port != b->port)
        return a->port < b->port ? -1 : 1;
    int result = strcmp(a->protocol, b->protocol);
    if (!result)
        result = strcmp(a->address, b->address);
    if (!result && a->pid != b->pid)
        result = a->pid < b->pid ? -1 : 1;
    if (!result && a->inode != b->inode)
        result = a->inode < b->inode ? -1 : 1;
    return result;
}

static double now(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time) < 0)
        return 0;
    return (double)time.tv_sec + (double)time.tv_nsec / 1000000000.0;
}

static int run_ss(unsigned first, unsigned last, enum pk_family family, char **output)
{
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC) < 0) {
        perror("portkeeper: pipe");
        return PK_ERROR;
    }
    char lower[32], upper[32];
    snprintf(lower, sizeof(lower), ":%u", first);
    snprintf(upper, sizeof(upper), ":%u", last);
    pid_t child = fork();
    if (child < 0) {
        perror("portkeeper: fork");
        close(pipes[0]);
        close(pipes[1]);
        return PK_ERROR;
    }
    if (child == 0) {
        close(pipes[0]);
        if (dup2(pipes[1], STDOUT_FILENO) < 0)
            _exit(126);
        close(pipes[1]);
        if (setenv("LC_ALL", "C", 1) < 0)
            _exit(126);
        char *args[18] = {"ss", "-H", "-l", "-n", "-t", "-u", "-p", "-O", "-e"};
        size_t next = 9;
        if (family != PK_ANY_FAMILY)
            args[next++] = family == PK_IPV4 ? "-4" : "-6";
        if (first) {
            args[next++] = "sport";
            args[next++] = first == last ? "=" : ">=";
            args[next++] = lower;
            if (first != last) {
                args[next++] = "and";
                args[next++] = "sport";
                args[next++] = "<=";
                args[next++] = upper;
            }
        }
        args[next] = NULL;
        execvp(args[0], args);
        int saved = errno;
        perror("portkeeper: cannot execute ss (install iproute2)");
        _exit(saved == ENOENT ? 127 : 126);
    }
    close(pipes[1]);
    int result = PK_OK;
    size_t length = 0, capacity = 8192;
    char *buffer = malloc(capacity);
    double deadline = now() + 15;
    if (!buffer) {
        perror("portkeeper: allocate ss output");
        result = PK_ERROR;
    }
    while (result == PK_OK) {
        if (pk_interrupted) {
            result = 128 + pk_interrupted;
            break;
        }
        if (now() > deadline) {
            fprintf(stderr, "portkeeper: ss timed out after 15 seconds\n");
            result = PK_DEPENDENCY;
            break;
        }
        struct pollfd descriptor = {.fd = pipes[0], .events = POLLIN};
        int ready = poll(&descriptor, 1, 100);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            perror("portkeeper: poll ss");
            result = PK_ERROR;
            break;
        }
        if (!ready)
            continue;
        if (length + 4097 > capacity) {
            if (capacity >= 16 * 1024 * 1024) {
                fprintf(stderr, "portkeeper: ss output exceeds 16 MiB limit\n");
                result = PK_ERROR;
                break;
            }
            capacity *= 2;
            char *larger = realloc(buffer, capacity);
            if (!larger) {
                perror("portkeeper: grow ss output");
                result = PK_ERROR;
                break;
            }
            buffer = larger;
        }
        ssize_t count = read(pipes[0], buffer + length, capacity - length - 1);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            perror("portkeeper: read ss");
            result = PK_ERROR;
            break;
        }
        if (!count)
            break;
        if (memchr(buffer + length, '\0', (size_t)count)) {
            fprintf(stderr, "portkeeper: unexpected NUL in ss output\n");
            result = PK_DEPENDENCY;
            break;
        }
        length += (size_t)count;
    }
    close(pipes[0]);
    /* Do not block indefinitely if a broken ss closes stdout but keeps running.
     * Never reap before cleanup: child PID cannot be reused while it is ours. */
    int status = 0;
    for (;;) {
        if (result != PK_OK)
            (void)kill(child, SIGKILL);
        pid_t waited = waitpid(child, &status, result == PK_OK ? WNOHANG : 0);
        if (waited == child)
            break;
        if (waited < 0 && errno != EINTR) {
            perror("portkeeper: wait for ss");
            result = PK_ERROR;
            break;
        }
        if (pk_interrupted)
            result = 128 + pk_interrupted;
        if (now() > deadline && result == PK_OK) {
            fprintf(stderr, "portkeeper: ss timed out after 15 seconds\n");
            result = PK_DEPENDENCY;
        }
        if (result == PK_OK)
            (void)poll(NULL, 0, 20);
    }
    if (result == PK_OK && (!WIFEXITED(status) || WEXITSTATUS(status) != 0)) {
        fprintf(stderr, "portkeeper: ss failed; check iproute2 installation and permissions\n");
        result = PK_DEPENDENCY;
    }
    if (result != PK_OK) {
        free(buffer);
        return result;
    }
    buffer[length] = '\0';
    *output = buffer;
    return PK_OK;
}

int pk_discover(unsigned first, unsigned last, const char *protocol,
                enum pk_family family, pk_snapshot *snapshot)
{
    char *output = NULL;
    int result = run_ss(first, last, family, &output);
    if (result != PK_OK)
        return result;
    char *save = NULL;
    size_t line_number = 0;
    for (char *line = strtok_r(output, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        ++line_number;
        if (strspn(line, " \t\r") == strlen(line))
            continue;
        if (pk_parse_line(line, snapshot) < 0) {
            fprintf(stderr, "portkeeper: cannot parse ss record %zu: %s\n",
                    line_number, strerror(errno));
            result = PK_DEPENDENCY;
            break;
        }
    }
    free(output);
    if (result != PK_OK) {
        pk_snapshot_free(snapshot);
        return result;
    }
    size_t kept = 0;
    for (size_t i = 0; i < snapshot->count; ++i) {
        pk_row *row = &snapshot->rows[i];
        if ((first && (row->port < first || row->port > last)) ||
            (protocol && strcmp(row->protocol, protocol) != 0))
            continue;
        pk_describe(row);
        snapshot->rows[kept++] = *row;
    }
    snapshot->count = kept;
    if (kept > 1) {
        qsort(snapshot->rows, kept, sizeof(*snapshot->rows), compare);
        kept = 1;
        for (size_t i = 1; i < snapshot->count; ++i)
            if (compare(&snapshot->rows[kept - 1], &snapshot->rows[i]))
                snapshot->rows[kept++] = snapshot->rows[i];
        snapshot->count = kept;
    }
    return pk_interrupted ? 128 + pk_interrupted : PK_OK;
}
