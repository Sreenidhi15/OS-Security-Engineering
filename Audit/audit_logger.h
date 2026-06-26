/*
 * audit_logger.h
 *
 * Audit logging module for the POSIX shell.
 *
 * NIST SP 800-53 Control Mapping:
 *   AU-2  — Audit Events: defines which events are logged (every command execution)
 *   AU-3  — Content of Audit Records: timestamp, UID, PID, command, exit status
 *   AU-12 — Audit Record Generation: the shell generates records at the point of execution
 *
 * Every command executed through the shell produces one log entry containing:
 *   - ISO 8601 timestamp
 *   - UID of the invoking user (getuid())
 *   - PID of the shell process
 *   - Full command string as entered
 *   - Exit status of the child process
 *
 * Log file: shell_audit.log (created in the working directory)
 * Log format: [TIMESTAMP] UID=<uid> PID=<pid> CMD="<command>" EXIT=<status>
 */

#ifndef AUDIT_LOGGER_H
#define AUDIT_LOGGER_H

#include <sys/types.h>

/* Opens the audit log file for appending. Call once at shell startup.
 * Returns 0 on success, -1 on failure. */
int audit_init(const char *logfile);

/* Writes one audit record. Call after every command execution.
 *   cmd       — the raw command string the user entered
 *   exit_code — exit status collected from waitpid()
 */
void audit_log(const char *cmd, int exit_code);

/* Flushes and closes the audit log. Call at shell exit. */
void audit_close(void);

#endif /* AUDIT_LOGGER_H */
