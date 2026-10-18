#include "portkeeper.h"

#include <errno.h>
#include <fcntl.h>
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
        "tcp LISTEN 0 1 *:80 *:* ino:18446744073709551616 sk:1"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        parse(invalid[i], &snapshot, 0);
    pk_snapshot_free(&snapshot);
    CHECK(snapshot.rows == NULL && snapshot.count == 0);

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(sock >= 0);
    struct stat st;
    CHECK(fstat(sock, &st) == 0);
    int procfd = pk_proc_open(getpid());
    CHECK(procfd >= 0);
    CHECK(pk_owns_socket(procfd, sock, (uint64_t)st.st_ino) == 0);
    CHECK(pk_owns_socket(procfd, sock, (uint64_t)st.st_ino + 1) < 0 && errno == ESTALE);
    close(sock);
    CHECK(pk_owns_socket(procfd, sock, (uint64_t)st.st_ino) < 0);
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
