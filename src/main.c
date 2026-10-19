#include "portkeeper.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void usage(FILE *stream)
{
    fputs("Usage:\n"
          "  portkeeper list [--protocol tcp|udp] [--json]\n"
          "  portkeeper inspect PORT [--protocol tcp|udp] [--json]\n"
          "  portkeeper stop PORT [--protocol tcp|udp] [--pid PID] [--dry-run] [--wait DURATION]\n"
          "  portkeeper --help | --version\n\n"
          "PORT is a decimal number from 1 to 65535. stop sends SIGTERM to\n"
          "all visible owners after you type 'yes'. --dry-run sends no signals.\n"
          "--pid selects one verified owner of the matching sockets for stop.\n"
          "--json writes a versioned JSON document for list/inspect.\n"
          "--wait verifies exit and rechecks sockets. DURATION is a positive whole\n"
          "number of seconds (3 or 3s) or milliseconds (250ms), at most 3600s.\n",
          stream);
}

static void interrupted(int signal_number)
{
    pk_interrupted = signal_number;
}

static void warn_unavailable(const pk_snapshot *snapshot)
{
    for (size_t i = 0; i < snapshot->count; ++i) {
        if (!snapshot->rows[i].pid) {
            fputs("portkeeper: some owners are unavailable (permissions or a process exited); "
                  "run with appropriate privileges for more visibility\n", stderr);
            break;
        }
    }
}

static void print_snapshot(const pk_snapshot *snapshot, int details)
{
    puts("PORT   PROTOCOL PID     PROCESS              LOCAL ADDRESS");
    for (size_t i = 0; i < snapshot->count; ++i) {
        const pk_row *row = &snapshot->rows[i];
        char pid[32];
        if (row->pid)
            snprintf(pid, sizeof(pid), "%ld", (long)row->pid);
        else {
            strcpy(pid, "-");
        }
        printf("%-6u %-8s %-7s %-20s %s\n", row->port, row->protocol,
               pid, row->command, row->address);
        if (details && row->pid) {
            char command[PK_CMDLINE_SIZE];
            int truncated;
            if (pk_command_line(row, command, &truncated) == 0)
                printf("  Command: %s%s\n", *command ? command : "<empty>",
                       truncated ? " [truncated]" : "");
            else
                printf("  Command: <unavailable: %s>\n", strerror(errno));
        }
    }
    warn_unavailable(snapshot);
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

static int verify_ownership(const pk_snapshot *snapshot, pk_target *targets, size_t count,
                            pid_t selected_pid)
{
    for (size_t i = 0; i < snapshot->count; ++i) {
        const pk_row *row = &snapshot->rows[i];
        if (selected_pid && row->pid != selected_pid)
            continue;
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

static int64_t monotonic_ms(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time) < 0)
        return -1;
    return (int64_t)time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

static int wait_for_exit(const pk_target *targets, size_t count, int wait_ms)
{
    struct pollfd *descriptors = calloc(count, sizeof(*descriptors));
    if (!descriptors) {
        perror("portkeeper: allocate exit monitors");
        return PK_ERROR;
    }
    for (size_t i = 0; i < count; ++i)
        descriptors[i] = (struct pollfd){.fd = targets[i].pidfd, .events = POLLIN};
    int result = PK_OK;
    int64_t started = monotonic_ms();
    if (started < 0) {
        perror("portkeeper: read monotonic clock");
        result = PK_ERROR;
        goto done;
    }
    printf("Waiting up to %d ms for %zu process(es) to exit.\n", wait_ms, count);
    if (fflush(stdout) == EOF) {
        perror("portkeeper: write wait status (SIGTERM already sent)");
        result = PK_ERROR;
        goto done;
    }
    size_t remaining = count;
    while (remaining) {
        if (pk_interrupted) {
            result = 128 + pk_interrupted;
            goto done;
        }
        int64_t current = monotonic_ms();
        if (current < 0) {
            perror("portkeeper: read monotonic clock");
            result = PK_ERROR;
            goto done;
        }
        int64_t left = started + wait_ms - current;
        /* Short polls also cover a signal arriving between the flag check
         * and poll. The deadline is shared by all targets, not per PID. */
        int timeout = left <= 0 ? 0 : left > 100 ? 100 : (int)left;
        int ready = poll(descriptors, (nfds_t)count, timeout);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            perror("portkeeper: poll process exits");
            result = PK_ERROR;
            goto done;
        }
        for (size_t i = 0; i < count; ++i) {
            if (descriptors[i].revents & (POLLERR | POLLNVAL)) {
                fprintf(stderr, "portkeeper: cannot monitor PID %ld for exit\n",
                        (long)targets[i].pid);
                result = PK_ERROR;
                goto done;
            }
            /* pidfds become readable on exit, including unreaped zombies. */
            if (descriptors[i].revents & (POLLIN | POLLHUP)) {
                printf("PID %ld exited.\n", (long)targets[i].pid);
                descriptors[i].fd = -1;
                --remaining;
            }
        }
        if (left <= 0)
            break;
    }
    printf("Processes: %zu/%zu exited.\n", count - remaining, count);
    if (remaining) {
        for (size_t i = 0; i < count; ++i)
            if (descriptors[i].fd >= 0)
                printf("PID %ld still running at the %d ms deadline.\n",
                       (long)targets[i].pid, wait_ms);
        result = PK_TIMEOUT;
    }
done:
    free(descriptors);
    return pk_interrupted ? 128 + pk_interrupted : result;
}

static int verify_stop_outcome(unsigned port, const char *protocol,
                               const pk_target *targets, size_t count, int wait_ms)
{
    int result = wait_for_exit(targets, count, wait_ms);
    if (result != PK_OK && result != PK_TIMEOUT)
        return result;
    pk_snapshot current = {0};
    int discovered = pk_discover(port, protocol, &current);
    if (discovered != PK_OK) {
        fputs("portkeeper: socket state could not be verified; SIGTERM was already sent\n",
              stderr);
        pk_snapshot_free(&current);
        return discovered;
    }
    const char *scope = protocol ? protocol : "TCP/UDP";
    if (current.count) {
        printf("Port %u: matching listening sockets remain (%s).\n", port, scope);
        print_snapshot(&current, 0);
        if (result == PK_OK)
            result = PK_OCCUPIED;
    } else {
        printf("Port %u: no matching listening sockets (%s) at verification.\n", port, scope);
    }
    pk_snapshot_free(&current);
    return result;
}

static int stop_port(unsigned port, const char *protocol, const pk_snapshot *snapshot,
                     int dry_run, int wait_ms, pid_t selected_pid)
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
        if (selected_pid && pid != selected_pid)
            continue;
        if (find_target(targets, count, pid))
            continue;
        if (pk_target_open(pid, &targets[count]) < 0) {
            result = target_error(pid, "prepare");
            goto done;
        }
        ++count;
    }
    if (!count) {
        fprintf(stderr, "portkeeper: PID %ld is not a verified owner of matching listening "
                "sockets on port %u; no signals sent\n", (long)selected_pid, port);
        result = PK_NOT_FOUND;
        goto done;
    }
    result = verify_ownership(snapshot, targets, count, selected_pid);
    if (result != PK_OK)
        goto done;
    if (selected_pid)
        printf("Only PID %ld is selected for SIGTERM.\n", (long)selected_pid);
    if (dry_run) {
        printf("Dry run: would send SIGTERM to %zu process(es). No signals sent.\n", count);
        goto done;
    }
    printf("SIGTERM will be sent to %zu process(es), affecting ALL their ports and work.\n"
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
    result = verify_ownership(snapshot, targets, count, selected_pid);
    if (result != PK_OK)
        goto done;
    size_t sent = 0;
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
        ++sent;
    }
    if (wait_ms && sent && !pk_interrupted) {
        int outcome = verify_stop_outcome(port, protocol, targets, sent, wait_ms);
        /* A delivery failure takes precedence over verification of the subset
         * that received SIGTERM. Never send signals to newly discovered owners. */
        if (result == PK_OK)
            result = outcome;
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
    int wait_ms = 0;
    int json = 0;
    pid_t selected_pid = 0;
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
        } else if (strcmp(argv[i], "--wait") == 0 && is_stop && !wait_ms && i + 1 < argc) {
            if (pk_wait_ms(argv[++i], &wait_ms) < 0)
                goto invalid;
        } else if (strcmp(argv[i], "--json") == 0 && !is_stop && !json) {
            json = 1;
        } else if (strcmp(argv[i], "--pid") == 0 && is_stop && !selected_pid && i + 1 < argc) {
            if (pk_pid(argv[++i], &selected_pid) < 0)
                goto invalid;
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
    if (result == PK_OK && json) {
        if (pk_print_json(stdout, &snapshot, !is_list) < 0 || fflush(stdout) == EOF) {
            perror("portkeeper: write JSON output");
            result = PK_ERROR;
        } else {
            warn_unavailable(&snapshot);
        }
    }
    if (result == PK_OK) {
        if (!snapshot.count && !is_list) {
            fprintf(stderr, "portkeeper: no matching listening sockets on port %u\n", port);
            result = PK_NOT_FOUND;
        } else {
            if (!json)
                print_snapshot(&snapshot, !is_list && !is_stop);
            /* Output must succeed before asking to perform a destructive action. */
            if (fflush(stdout) == EOF) {
                perror("portkeeper: write output");
                result = PK_ERROR;
            } else if (is_stop) {
                result = stop_port(port, protocol, &snapshot, dry_run, wait_ms, selected_pid);
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
