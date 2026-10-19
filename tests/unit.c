#include "portkeeper.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

static void parse(const char *input, pk_snapshot *snapshot, int valid)
{
    char *line = strdup(input);
    CHECK(line != NULL);
    CHECK((pk_parse_line(line, snapshot) == 0) == valid);
    free(line);
}

static void compatibility_fixtures(void)
{
    const char *versions[] = {"5.5", "5.15", "6.1"};
    const pk_row expected[] = {
        {.port = 3000, .protocol = "TCP", .address = "127.0.0.1:3000",
         .inode = 70001, .pid = 1001, .fd = 3},
        {.port = 3000, .protocol = "TCP", .address = "127.0.0.1:3000",
         .inode = 70001, .pid = 1002, .fd = 3},
        {.port = 5353, .protocol = "UDP", .address = "127.0.0.1:5353",
         .inode = 70002, .pid = 1001, .fd = 4},
        {.port = 8080, .protocol = "TCP", .address = "[::1]:8080",
         .inode = 70003, .pid = 1001, .fd = 5},
        {.port = 5354, .protocol = "UDP", .address = "[::1]:5354",
         .inode = 70004, .pid = 1001, .fd = 6},
        {.port = 9000, .protocol = "TCP", .address = "127.0.0.1:9000",
         .inode = 70005, .pid = 0, .fd = -1}
    };
    for (size_t version = 0; version < sizeof(versions) / sizeof(versions[0]); ++version) {
        char path[4096];
        CHECK(snprintf(path, sizeof(path), "%s/iproute2-%s.txt",
                       PK_FIXTURE_DIR, versions[version]) < (int)sizeof(path));
        FILE *file = fopen(path, "r");
        CHECK(file != NULL);
        pk_snapshot snapshot = {0};
        char *line = NULL;
        size_t size = 0;
        while (getline(&line, &size, file) >= 0)
            CHECK(pk_parse_line(line, &snapshot) == 0);
        CHECK(!ferror(file));
        free(line);
        CHECK(fclose(file) == 0);
        CHECK(snapshot.count == sizeof(expected) / sizeof(expected[0]));
        unsigned seen = 0;
        for (size_t i = 0; i < snapshot.count; ++i) {
            const pk_row *actual = &snapshot.rows[i];
            size_t j;
            for (j = 0; j < sizeof(expected) / sizeof(expected[0]); ++j)
                if (actual->port == expected[j].port && actual->pid == expected[j].pid)
                    break;
            CHECK(j < sizeof(expected) / sizeof(expected[0]));
            CHECK(!(seen & (1u << j)));
            seen |= 1u << j;
            CHECK(strcmp(actual->protocol, expected[j].protocol) == 0);
            CHECK(strcmp(actual->address, expected[j].address) == 0);
            CHECK(actual->inode == expected[j].inode && actual->fd == expected[j].fd);
        }
        pk_snapshot_free(&snapshot);
    }
}

static void json_strings(void)
{
    pk_row rows[] = {
        {.port = 3000, .protocol = "TCP", .address = "127.0.0.1:3000",
         .pid = 123, .command = "quote\" slash\\ control\n\t\001\177\200",
         .command_available = 1},
        {.port = 5353, .protocol = "UDP", .address = "[::1]:5353", .pid = 0},
        {.port = 8080, .protocol = "TCP", .address = "*:8080", .pid = 456}
    };
    pk_snapshot snapshot = {.rows = rows, .count = 3};
    char *output = NULL;
    size_t size = 0;
    FILE *stream = open_memstream(&output, &size);
    CHECK(stream != NULL);
    CHECK(pk_print_json(stream, &snapshot, 0) == 0);
    CHECK(fclose(stream) == 0);
    CHECK(strstr(output, "quote\\\" slash\\\\ control\\u000a\\u0009\\u0001\\u007f\\u0080"));
    CHECK(strstr(output, "\"pid\":null,\"process\":null"));
    CHECK(strstr(output, "\"pid\":456,\"process\":null"));
    CHECK(strstr(output, "command_line") == NULL);
    CHECK(size == strlen(output) && output[size - 1] == '\n');
    for (size_t i = 0; i < size - 1; ++i)
        CHECK((unsigned char)output[i] >= 32 && (unsigned char)output[i] < 127);
    free(output);

    snapshot = (pk_snapshot){0};
    stream = open_memstream(&output, &size);
    CHECK(stream != NULL && pk_print_json(stream, &snapshot, 1) == 0);
    CHECK(fclose(stream) == 0);
    CHECK(strcmp(output, "{\"schema_version\":1,\"sockets\":[]}\n") == 0);
    free(output);
}

int main(void)
{
    unsigned port = 0;
    CHECK(pk_port("1", &port) == 0 && port == 1);
    CHECK(pk_port("65535", &port) == 0 && port == 65535);
    CHECK(pk_port("00080", &port) == 0 && port == 80);
    const char *bad[] = {"", "0", "65536", "-1", "+80", " 80", "80 ",
                         "80;id", "80/tcp", "9999999999999999999999999999"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        CHECK(pk_port(bad[i], &port) < 0);
    pid_t pid;
    CHECK(pk_pid("1", &pid) == 0 && pid == 1);
    CHECK(pk_pid("00123", &pid) == 0 && pid == 123);
    char maximum_pid[32];
    snprintf(maximum_pid, sizeof(maximum_pid), "%d", INT_MAX);
    CHECK(pk_pid(maximum_pid, &pid) == 0 && pid == INT_MAX);
    snprintf(maximum_pid, sizeof(maximum_pid), "%llu", (unsigned long long)INT_MAX + 1);
    CHECK(pk_pid(maximum_pid, &pid) < 0);
    const char *bad_pid[] = {"", "0", "-1", "+1", " 1", "1 ", "1.0", "1;id",
                             "99999999999999999999999999"};
    for (size_t i = 0; i < sizeof(bad_pid) / sizeof(bad_pid[0]); ++i)
        CHECK(pk_pid(bad_pid[i], &pid) < 0);
    int milliseconds;
    CHECK(pk_wait_ms("3", &milliseconds) == 0 && milliseconds == 3000);
    CHECK(pk_wait_ms("3s", &milliseconds) == 0 && milliseconds == 3000);
    CHECK(pk_wait_ms("250ms", &milliseconds) == 0 && milliseconds == 250);
    CHECK(pk_wait_ms("1ms", &milliseconds) == 0 && milliseconds == 1);
    CHECK(pk_wait_ms("3600s", &milliseconds) == 0 && milliseconds == 3600000);
    CHECK(pk_wait_ms("3600000ms", &milliseconds) == 0 && milliseconds == 3600000);
    const char *bad_wait[] = {"", "0", "0ms", "-1", "+1s", "1.5s", "1m", "s",
                             "1 s", " 1s", "1s ", "1MS", "3601s", "3600001ms",
                             "999999999999999999999999999", "18446744073709551615s"};
    for (size_t i = 0; i < sizeof(bad_wait) / sizeof(bad_wait[0]); ++i)
        CHECK(pk_wait_ms(bad_wait[i], &milliseconds) < 0);
    char dirty[] = "hi\033[31m\t\n\377";
    pk_sanitize(dirty);
    CHECK(strcmp(dirty, "hi?[31m???") == 0);

    pk_snapshot snapshot = {0};
    parse("tcp LISTEN 0 128 127.0.0.1:3000 0.0.0.0:* "
          "users:((\"name with spaces\",pid=123,fd=4),(\"worker\",pid=456,fd=5)) "
          "uid:1000 ino:999 sk:1 cgroup:/test <->", &snapshot, 1);
    CHECK(snapshot.count == 2 && snapshot.rows[0].port == 3000);
    CHECK(snapshot.rows[0].pid == 123 && snapshot.rows[1].pid == 456);
    CHECK(snapshot.rows[0].inode == 999 && snapshot.rows[1].fd == 5);
    parse("udp UNCONN 0 0 [fe80::1%eth0]:5353 [::]:* ino:44 sk:2 v6only:1 <->",
          &snapshot, 1);
    CHECK(snapshot.count == 3 && snapshot.rows[2].pid == 0);
    CHECK(strcmp(snapshot.rows[2].address, "[fe80::1%eth0]:5353") == 0);
    parse("udp UNCONN 0 0 *:53 *:* users:((\"odd ) name\",pid=789,fd=0)) "
          "ino:45 sk:3 <->", &snapshot, 1);
    CHECK(snapshot.rows[3].fd == 0);
    parse("tcp LISTEN 0 0 *:80 *:* users:((\"x ino:7 sk:f\",pid=2,fd=3)) "
          "ino:100 sk:4 <->", &snapshot, 1);
    CHECK(snapshot.rows[4].inode == 100);
    const char *invalid[] = {
        "", "tcp LISTEN", "sctp LISTEN 0 1 *:80 *:* ino:1 sk:1",
        "tcp ESTAB 0 1 *:80 *:* ino:1 sk:1", "tcp LISTEN 0 1 *:0 *:* ino:1 sk:1",
        "tcp LISTEN 0 1 *:65536 *:* ino:1 sk:1", "tcp LISTEN 0 1 *:80 *:*",
        "tcp LISTEN 0 1 *:80 *:* ino:0 sk:1",
        "tcp LISTEN 0 1 *:80 *:* ino:18446744073709551616 sk:1",
        "tcp LISTEN 0 1 *:80 *:* users:((\"ok\",pid=123,fd=4),"
        "(\"bad\",pid=99999999999999999999999999,fd=5)) ino:1 sk:1",
        "tcp LISTEN 0 1 *:80 *:* users:((\"ok\",pid=123,fd=4),"
        "(\"bad\",pid=456,fd=99999999999999999999999999)) ino:1 sk:1",
        "tcp LISTEN 0 1 *:80 *:* users:((\"bad\",pid=123,fd=nope)) ino:1 sk:1"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        parse(invalid[i], &snapshot, 0);
    pk_snapshot_free(&snapshot);
    CHECK(snapshot.rows == NULL && snapshot.count == 0);
    compatibility_fixtures();
    json_strings();

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(sock >= 0);
    struct stat st;
    CHECK(fstat(sock, &st) == 0);
    int procfd = pk_proc_open(getpid());
    CHECK(procfd >= 0);
    CHECK(pk_owns_socket(procfd, sock, (uint64_t)st.st_ino) == 0);
    CHECK(pk_owns_socket(procfd, sock, (uint64_t)st.st_ino + 1) < 0 && errno == ESTALE);
    pk_row own = {.pid = getpid(), .fd = sock, .inode = (uint64_t)st.st_ino};
    char command[PK_CMDLINE_SIZE];
    int truncated;
    CHECK(pk_command_line(&own, command, &truncated) == 0 && !truncated && *command);
    ++own.inode;
    CHECK(pk_command_line(&own, command, &truncated) < 0 && errno == ESTALE);
    --own.inode;
    close(sock);
    CHECK(pk_owns_socket(procfd, sock, (uint64_t)st.st_ino) < 0);
    CHECK(pk_command_line(&own, command, &truncated) < 0);
    close(procfd);

    pk_target target;
    CHECK(pk_target_open(1, &target) < 0 && errno == EPERM);
    CHECK(pk_target_open(getpid(), &target) < 0 && errno == EPERM);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        for (;;)
            pause();
    }
    CHECK(pk_target_open(child, &target) == 0);
    CHECK(pk_target_signal(&target, 0) == 0);
    CHECK(pk_target_signal(&target, SIGTERM) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
    CHECK(pk_target_signal(&target, 0) < 0 && errno == ESRCH);
    pk_target_close(&target);
    puts("unit tests passed");
    return 0;
}
