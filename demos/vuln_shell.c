/*
 * vuln_shell.c
 *
 * INTENTIONALLY VULNERABLE SHELL — FOR EDUCATIONAL PURPOSES ONLY
 *
 * This file demonstrates CWE-78: Improper Neutralization of Special Elements
 * used in an OS Command ('OS Command Injection').
 *
 * The vulnerability: this shell uses system() to execute user input directly.
 * system() passes the command string to /bin/sh -c, which means shell
 * metacharacters like ; | && || ` $() are interpreted by the shell before
 * execution. An attacker who controls any part of the input string can inject
 * arbitrary commands.
 *
 * NIST SP 800-53 Control Failure:
 *   SI-10 — Information Input Validation: no validation or sanitization of
 *            user-supplied input before it is passed to a privileged API.
 *
 * CWE:  CWE-78 (OS Command Injection)
 * CVSS: High (8.8) when exploited in a setuid context
 *
 * Compare with safe_shell.c which uses execvp() and is not vulnerable.
 *
 * Compile: gcc -o vuln_shell vuln_shell.c
 * Run:     ./vuln_shell
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE 1024

int main(void) {
    char input[MAX_LINE];

    printf("=== VULNERABLE SHELL (uses system()) ===\n");
    printf("This shell is intentionally vulnerable to command injection.\n");
    printf("Try: ls ; whoami\n");
    printf("Try: echo hello && cat /etc/passwd\n\n");

    while (1) {
        printf("vuln$ ");
        fflush(stdout);

        if (fgets(input, MAX_LINE, stdin) == NULL) {
            printf("\n");
            break;
        }

        /* strip trailing newline */
        input[strcspn(input, "\n")] = '\0';

        if (strcmp(input, "exit") == 0)
            break;

        if (strlen(input) == 0)
            continue;

        /*
         * VULNERABILITY: system() passes input directly to /bin/sh -c
         *
         * The programmer's intent: run a single command like "ls" or "pwd".
         * The attacker's reality: input "ls ; cat /etc/shadow" runs TWO
         * commands because /bin/sh interprets the semicolon as a separator.
         *
         * No amount of careful coding elsewhere fixes this — the root cause
         * is the choice of system() over execvp().
         */
        system(input);  /* VULNERABLE: do not use system() with user input */
    }

    return 0;
}
