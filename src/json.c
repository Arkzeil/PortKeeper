#include "portkeeper.h"

#include <string.h>

/* Discovery and proc descriptions are sanitized to ASCII. Escape every byte
 * outside printable ASCII as well, so all inputs produce valid JSON strings. */
static void string(FILE *stream, const char *value)
{
    if (!value) {
        fputs("null", stream);
        return;
    }
    fputc('"', stream);
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            fputc('\\', stream);
            fputc(*p, stream);
        } else if (*p < 32 || *p >= 127) {
            fprintf(stream, "\\u%04x", (unsigned)*p);
        } else {
            fputc(*p, stream);
        }
    }
    fputc('"', stream);
}

int pk_print_json(FILE *stream, const pk_snapshot *snapshot, int details)
{
    fputs("{\"schema_version\":1,\"sockets\":[", stream);
    for (size_t i = 0; i < snapshot->count; ++i) {
        const pk_row *row = &snapshot->rows[i];
        if (i)
            fputc(',', stream);
        fprintf(stream, "{\"port\":%u,\"protocol\":", row->port);
        string(stream, strcmp(row->protocol, "TCP") == 0 ? "tcp" : "udp");
        fputs(",\"local_address\":", stream);
        string(stream, row->address);
        fputs(",\"pid\":", stream);
        if (row->pid)
            fprintf(stream, "%ld", (long)row->pid);
        else
            fputs("null", stream);
        fputs(",\"process\":", stream);
        string(stream, row->pid && row->command_available ? row->command : NULL);
        if (details) {
            char command[PK_CMDLINE_SIZE];
            int truncated = 0;
            int available = row->pid && pk_command_line(row, command, &truncated) == 0;
            fputs(",\"command_line\":", stream);
            string(stream, available ? command : NULL);
            fputs(",\"command_line_truncated\":", stream);
            fputs(available ? (truncated ? "true" : "false") : "null", stream);
        }
        fputc('}', stream);
    }
    fputs("]}\n", stream);
    return ferror(stream) ? -1 : 0;
}
