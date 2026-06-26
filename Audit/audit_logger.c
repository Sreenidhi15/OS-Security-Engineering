/*
 * audit_logger.c
 *
 * Implementation of the audit logging module.
 *
 * NIST SP 800-53 Control Mapping:
 *   AU-2  — Audit Events
 *   AU-3  — Content of Audit Records
 *   AU-9  — Protection of Audit Information (O_APPEND ensures atomic writes;
 *            log file should be chmod 600 and owned by root in production)
 *   AU-12 — Audit Record Generation
 *
 * Design decisions:
 *   - O_APPEND flag guarantees each write is atomic at the OS level,
 *     preventing interleaved entries if multiple shell instances run concurrently.
 *   - getuid() captures the real UID of the invoking user, not the effective UID,
 *     so setuid wrappers do not obscure who ran the command.
 *   - strftime() with %z produces timezone-aware timestamps (e.g. 2026-06-26T14:32:01-0400)
 *     which is required for forensic log correlation.
 *   - All writes use a single fprintf() call to minimize the window for
 *     partial-write corruption.
 */

#include "audit_logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

static FILE *log_fp = NULL;  /* file handle kept open for the shell lifetime */

/*
 * audit_init — open the log file for appending.
 * Using "a" mode sets O_APPEND internally; every fwrite is atomic up to PIPE_BUF.
 */
int audit_init(const char *logfile) {
    log_fp = fopen(logfile, "a");
    if (log_fp == NULL) {
        perror("audit_init: could not open log file");
        return -1;
    }

    /* Write a session start marker so log readers can distinguish shell sessions */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S%z", tm_info);

    fprintf(log_fp,
        "--- SESSION START | TIME=%s | UID=%d | PID=%d ---\n",
        timestamp,
        (int)getuid(),
        (int)getpid()
    );
    fflush(log_fp);
    return 0;
}

/*
 * audit_log — write one audit record for a command execution.
 *
 * Record format:
 *   [2026-06-26T14:32:01-0400] UID=1001 PID=4823 CMD="ls -la | grep .c" EXIT=0
 *
 * EXIT=-1 indicates the child exit status was not collected (background process).
 */
void audit_log(const char *cmd, int exit_code) {
    if (log_fp == NULL)
        return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S%z", tm_info);

    fprintf(log_fp,
        "[%s] UID=%d PID=%d CMD=\"%s\" EXIT=%d\n",
        timestamp,
        (int)getuid(),
        (int)getpid(),
        cmd,
        exit_code
    );
    fflush(log_fp);  /* flush after every record; do not buffer audit entries */
}

/*
 * audit_close — write a session end marker and close the log.
 */
void audit_close(void) {
    if (log_fp == NULL)
        return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S%z", tm_info);

    fprintf(log_fp,
        "--- SESSION END   | TIME=%s | UID=%d | PID=%d ---\n\n",
        timestamp,
        (int)getuid(),
        (int)getpid()
    );
    fclose(log_fp);
    log_fp = NULL;
}
