#include "portkeeper.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *stream)
{
    fputs("Usage:\n"
          "  portkeeper list [--protocol tcp|udp]\n"
          "  portkeeper inspect PORT [--protocol tcp|udp]\n"
          "  portkeeper stop PORT [--protocol tcp|udp] [--dry-run]\n"
          "  portkeeper --help | --version\n\n"
          "PORT is a decimal number from 1 to 65535. stop sends SIGTERM to\n"
          "all visible owners after you type 'yes'. --dry-run sends no signals.\n",
          stream);
}

static void interrupted(int signal_number)
{
    pk_interrupted = signal_number;
}

static void print_snapshot(const pk_snapshot *snapshot, int details)
{
    puts("PORT   PROTOCOL PID     PROCESS              LOCAL ADDRESS");
    int unavailable = 0;
    for (size_t i = 0; i < snapshot->count; ++i) {
        const pk_row *row = &snapshot->rows[i];
        char pid[32];
        if (row->pid)
            snprintf(pid, sizeof(pid), "%ld", (long)row->pid);
        else {
            strcpy(pid, "-");
            unavailable = 1;
        }
        printf("%-6u %-8s %-7s %-20s %s\n", row->port, row->protocol,
               pid, row->command, row->address);
        if (details && row->pid) {
            char command[4096];
            if (pk_command_line(row->pid, command, sizeof(command)) == 0)
                printf("  Command: %s%s\n", *command ? command : "<empty>",
                       strlen(command) == sizeof(command) - 1 ? " [truncated]" : "");
            else
                printf("  Command: <unavailable: %s>\n", strerror(errno));
        }
    }
    if (unavailable)
        fputs("portkeeper: some owners are unavailable (permissions or a process exited); "
              "run with appropriate privileges for more visibility\n", stderr);
}

static int target_error(pid_t pid, const char *operation)
{
    int saved = errno;
    fprintf(stderr, "portkeeper: cannot %s PID %ld: %s\n",
            operation, (long)pid, strerror(saved));
    if (saved == EACCES || saved == EPERM)
        return PK_PERMISSION;
    if (saved == ENOENT || saved == ESRCH || saved == ESTALE)
        return PK_CHANGED;
    if (saved == ENOSYS) {
        fputs("portkeeper: stop requires Linux pidfd support (Linux 5.3+); "
              "no unsafe PID-based fallback is used\n", stderr);
        return PK_DEPENDENCY;
    }
    return PK_ERROR;
}

static pk_target *find_target(pk_target *targets, size_t count, pid_t pid)
{
    for (size_t i = 0; i < count; ++i)
        if (targets[i].pid == pid)
            return &targets[i];
    return NULL;
}

static int verify_ownership(const pk_snapshot *snapshot, pk_target *targets, size_t count)
{
    for (size_t i = 0; i < snapshot->count; ++i) {
        const pk_row *row = &snapshot->rows[i];
        pk_target *target = find_target(targets, count, row->pid);
        if (!target) {
            fputs("portkeeper: owner set changed; run the command again\n", stderr);
            return PK_CHANGED;
        }
        if (pk_target_signal(target, 0) < 0)
            return target_error(row->pid, "check");
        if (pk_owns_socket(target->procfd, row->fd, row->inode) < 0)
            return target_error(row->pid, "verify socket ownership for");
    }
    return PK_OK;
}

static int same_snapshot(const pk_snapshot *a, const pk_snapshot *b)
{
    if (a->count != b->count)
        return 0;
    for (size_t i = 0; i < a->count; ++i) {
        const pk_row *x = &a->rows[i], *y = &b->rows[i];
        if (x->port != y->port || x->pid != y->pid || x->fd != y->fd ||
            x->inode != y->inode || strcmp(x->protocol, y->protocol) ||
            strcmp(x->address, y->address))
            return 0;
    }
    return 1;
}

static int stop_port(unsigned port, const char *protocol, const pk_snapshot *snapshot,
                     int dry_run)
{
    pk_target *targets = calloc(snapshot->count, sizeof(*targets));
    if (!targets) {
        perror("portkeeper: allocate targets");
        return PK_ERROR;
    }
    size_t count = 0;
    int result = PK_OK;
    for (size_t i = 0; i < snapshot->count; ++i) {
        pid_t pid = snapshot->rows[i].pid;
        if (!pid) {
            fputs("portkeeper: refusing stop: at least one socket owner cannot be verified; "
                  "no signals sent\n", stderr);
            result = PK_PERMISSION;
            goto done;
        }
        if (find_target(targets, count, pid))
            continue;
        if (pk_target_open(pid, &targets[count]) < 0) {
            result = target_error(pid, "prepare");
            goto done;
        }
        ++count;
    }
    result = verify_ownership(snapshot, targets, count);
    if (result != PK_OK)
        goto done;
    if (dry_run) {
        printf("Dry run: would send SIGTERM to %zu process(es). No signals sent.\n", count);
        goto done;
    }
    printf("SIGTERM will terminate %zu process(es), affecting ALL their ports and work.\n"
           "Type 'yes' to continue: ", count);
    if (fflush(stdout) == EOF) {
        perror("portkeeper: write output");
        result = PK_ERROR;
        goto done;
    }
    char answer[32];
    if (pk_interrupted || !fgets(answer, sizeof(answer), stdin) ||
        (strcmp(answer, "yes\n") != 0 && strcmp(answer, "yes") != 0)) {
        if (ferror(stdin) && !pk_interrupted) {
            perror("portkeeper: read confirmation");
            result = PK_ERROR;
        } else {
            fputs("portkeeper: cancelled; no signals sent\n", stderr);
            result = pk_interrupted ? 128 + pk_interrupted : PK_CANCELLED;
        }
        goto done;
    }
    if (pk_interrupted) {
        result = 128 + pk_interrupted;
        goto done;
    }
    pk_snapshot fresh = {0};
    result = pk_discover(port, protocol, &fresh);
    if (result == PK_OK && !same_snapshot(snapshot, &fresh)) {
        fputs("portkeeper: sockets or owners changed during confirmation; "
              "no signals sent, run the command again\n", stderr);
        result = PK_CHANGED;
    }
    pk_snapshot_free(&fresh);
    if (result != PK_OK)
        goto done;
    result = verify_ownership(snapshot, targets, count);
    if (result != PK_OK)
        goto done;
    for (size_t i = 0; i < count; ++i) {
        if (pk_interrupted) {
            result = 128 + pk_interrupted;
            break;
        }
        if (pk_target_signal(&targets[i], SIGTERM) < 0) {
            result = target_error(targets[i].pid, "send SIGTERM to");
            fprintf(stderr, "portkeeper: %zu of %zu process(es) already signaled\n", i, count);
            break;
        }
        printf("Sent SIGTERM to PID %ld.\n", (long)targets[i].pid);
    }
done:
    for (size_t i = 0; i < count; ++i)
        pk_target_close(&targets[i]);
    free(targets);
    return result;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return PK_OK;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("portkeeper 0.1.0");
        return PK_OK;
    }
    if (argc < 2 || (strcmp(argv[1], "list") && strcmp(argv[1], "inspect") &&
                     strcmp(argv[1], "stop"))) {
        usage(stderr);
        return PK_USAGE;
    }
    int is_list = strcmp(argv[1], "list") == 0;
    int is_stop = strcmp(argv[1], "stop") == 0;
    unsigned port = 0;
    const char *protocol = NULL;
    int dry_run = 0;
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--protocol") == 0 && !protocol && i + 1 < argc) {
            const char *value = argv[++i];
            if (strcmp(value, "tcp") == 0)
                protocol = "TCP";
            else if (strcmp(value, "udp") == 0)
                protocol = "UDP";
            else
                goto invalid;
        } else if (strcmp(argv[i], "--dry-run") == 0 && is_stop && !dry_run) {
            dry_run = 1;
        } else if (!is_list && !port && pk_port(argv[i], &port) == 0) {
            /* Strict numeric conversion; no shell or ss expression input. */
        } else {
            goto invalid;
        }
    }
    if (!is_list && !port)
        goto invalid;
    if (geteuid() != getuid() || getegid() != getgid()) {
        fputs("portkeeper: setuid/setgid execution is unsupported\n", stderr);
        return PK_PERMISSION;
    }
    struct sigaction action = {0};
    action.sa_handler = interrupted;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) < 0 || sigaction(SIGTERM, &action, NULL) < 0 ||
        sigaction(SIGHUP, &action, NULL) < 0) {
        perror("portkeeper: install signal handlers");
        return PK_ERROR;
    }
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL) < 0) {
        perror("portkeeper: ignore SIGPIPE");
        return PK_ERROR;
    }
    pk_snapshot snapshot = {0};
    int result = pk_discover(port, protocol, &snapshot);
    if (result == PK_OK) {
        if (!snapshot.count && !is_list) {
            fprintf(stderr, "portkeeper: no matching listening sockets on port %u\n", port);
            result = PK_NOT_FOUND;
        } else {
            print_snapshot(&snapshot, !is_list && !is_stop);
            /* Output must succeed before asking to perform a destructive action. */
            if (fflush(stdout) == EOF) {
                perror("portkeeper: write output");
                result = PK_ERROR;
            } else if (is_stop) {
                result = stop_port(port, protocol, &snapshot, dry_run);
            }
        }
    }
    pk_snapshot_free(&snapshot);
    if (pk_interrupted) {
        fprintf(stderr, "portkeeper: interrupted by signal %d\n", (int)pk_interrupted);
        result = 128 + pk_interrupted;
    }
    if (fflush(stdout) == EOF && result == PK_OK) {
        perror("portkeeper: write output");
        result = PK_ERROR;
    }
    return result;
invalid:
    fputs("portkeeper: invalid arguments\n", stderr);
    usage(stderr);
    return PK_USAGE;
}
