#ifndef PORTKEEPER_H
#define PORTKEEPER_H

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#define PK_CMDLINE_SIZE 4096

enum pk_exit {
    PK_OK = 0, PK_ERROR = 1, PK_USAGE = 2, PK_NOT_FOUND = 3,
    PK_DEPENDENCY = 4, PK_PERMISSION = 5, PK_CHANGED = 6, PK_CANCELLED = 7,
    PK_TIMEOUT = 8, PK_OCCUPIED = 9
};

enum pk_family { PK_ANY_FAMILY = 0, PK_IPV4 = 4, PK_IPV6 = 6 };

typedef struct {
    unsigned port;
    char protocol[4];
    char address[256];
    uint64_t inode;
    pid_t pid;
    int fd;
    char command[256];
    int command_available;
} pk_row;

typedef struct {
    pk_row *rows;
    size_t count;
    size_t capacity;
} pk_snapshot;

typedef struct {
    pid_t pid;
    int procfd;
    int pidfd;
} pk_target;

extern volatile sig_atomic_t pk_interrupted;
int pk_port(const char *text, unsigned *port);
int pk_pid(const char *text, pid_t *pid);
int pk_wait_ms(const char *text, int *milliseconds);
void pk_sanitize(char *text);
int pk_parse_line(char *line, pk_snapshot *snapshot);
void pk_snapshot_free(pk_snapshot *snapshot);
int pk_discover(unsigned port, const char *protocol, enum pk_family family, pk_snapshot *snapshot);
int pk_proc_open(pid_t pid);
int pk_owns_socket(int procfd, int fd, uint64_t inode);
void pk_describe(pk_row *row);
int pk_command_line(const pk_row *row, char buffer[PK_CMDLINE_SIZE], int *truncated);
int pk_print_json(FILE *stream, const pk_snapshot *snapshot, int details);
int pk_target_open(pid_t pid, pk_target *target);
int pk_target_signal(const pk_target *target, int signal_number);
void pk_target_close(pk_target *target);

#endif
