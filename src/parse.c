#include "portkeeper.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int number(const char *text, const char **end, uint64_t *value)
{
    if (!isdigit((unsigned char)*text))
        return -1;
    errno = 0;
    char *tail;
    unsigned long long parsed = strtoull(text, &tail, 10);
    if (errno == ERANGE)
        return -1;
    *value = (uint64_t)parsed;
    *end = tail;
    return 0;
}

int pk_port(const char *text, unsigned *port)
{
    uint64_t value;
    const char *end;
    if (number(text, &end, &value) < 0 || *end || value == 0 || value > 65535)
        return -1;
    *port = (unsigned)value;
    return 0;
}

void pk_sanitize(char *text)
{
    for (unsigned char *p = (unsigned char *)text; *p; ++p)
        if (*p < 32 || *p >= 127)
            *p = '?';
}

static int append(pk_snapshot *snapshot, const pk_row *row)
{
    if (snapshot->count >= 100000) {
        errno = EOVERFLOW;
        return -1;
    }
    if (snapshot->count == snapshot->capacity) {
        size_t capacity = snapshot->capacity ? snapshot->capacity * 2 : 32;
        pk_row *rows = realloc(snapshot->rows, capacity * sizeof(*rows));
        if (!rows)
            return -1;
        snapshot->rows = rows;
        snapshot->capacity = capacity;
    }
    snapshot->rows[snapshot->count++] = *row;
    return 0;
}

/* ss -H -l -n -t -u -p -O -e: six columns, then optional metadata.
 * Names from users:(...) are deliberately ignored: they are untrusted text.
 * PID/fd claims are verified against /proc before use. */
int pk_parse_line(char *line, pk_snapshot *snapshot)
{
    char *fields[6];
    char *cursor = line;
    for (size_t i = 0; i < 6; ++i) {
        while (isspace((unsigned char)*cursor))
            ++cursor;
        if (!*cursor) {
            errno = EPROTO;
            return -1;
        }
        fields[i] = cursor;
        while (*cursor && !isspace((unsigned char)*cursor))
            ++cursor;
        if (*cursor)
            *cursor++ = '\0';
    }
    pk_row row = {0};
    row.fd = -1;
    if (strcmp(fields[0], "tcp") == 0 && strcmp(fields[1], "LISTEN") == 0)
        strcpy(row.protocol, "TCP");
    else if (strcmp(fields[0], "udp") == 0 && strcmp(fields[1], "UNCONN") == 0)
        strcpy(row.protocol, "UDP");
    else {
        errno = EPROTO;
        return -1;
    }
    char *colon = strrchr(fields[4], ':');
    if (!colon || pk_port(colon + 1, &row.port) < 0 ||
        strlen(fields[4]) >= sizeof(row.address)) {
        errno = EPROTO;
        return -1;
    }
    strcpy(row.address, fields[4]);
    pk_sanitize(row.address);

    /* Extended metadata always has ino: followed by sk:. Choose the last
     * such pair to avoid a process name containing a fake metadata token. */
    const char *search = cursor;
    const char *inode_field = NULL;
    while ((search = strstr(search, "ino:")) != NULL) {
        const char *end;
        uint64_t inode;
        if ((search == cursor || isspace((unsigned char)search[-1])) &&
            number(search + 4, &end, &inode) == 0 &&
            strncmp(end, " sk:", 4) == 0 && inode != 0) {
            row.inode = inode;
            inode_field = search;
        }
        search += 4;
    }
    if (!inode_field) {
        errno = EPROTO;
        return -1;
    }

    size_t before = snapshot->count;
    search = cursor;
    while ((search = strstr(search, ",pid=")) != NULL && search < inode_field) {
        const char *end;
        uint64_t pid, fd;
        const char *start = search + 5;
        search = start;
        if (number(start, &end, &pid) < 0 || pid == 0 || pid > INT_MAX ||
            strncmp(end, ",fd=", 4) != 0)
            continue;
        if (number(end + 4, &end, &fd) < 0 || fd > INT_MAX || *end != ')')
            continue;
        row.pid = (pid_t)pid;
        row.fd = (int)fd;
        if (append(snapshot, &row) < 0)
            return -1;
    }
    if (snapshot->count == before) {
        row.pid = 0;
        row.fd = -1;
        return append(snapshot, &row);
    }
    return 0;
}

void pk_snapshot_free(pk_snapshot *snapshot)
{
    free(snapshot->rows);
    memset(snapshot, 0, sizeof(*snapshot));
}
