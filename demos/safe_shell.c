/*
 * safe_shell.c
 *
 * HARDENED SHELL — demonstrates the correct approach to command execution.
 *
 * This file demonstrates the fix for CWE-78: OS Command Injection.
 *
 * The fix: use execvp() instead of system(). execvp() takes an array of
 * argument strings and passes them directly to the kernel's execve() syscall.
 * The kernel does NOT invoke a shell interpreter — there is no /bin/sh -c,
 * so shell metacharacters like ; | && ` $() have no special meaning.
 * They are passed as literal argument strings to the program.
 *
 * An attacker who inputs "ls ; cat /etc/shadow" gets:
 *   execvp("ls", ["ls", ";", "cat", "/etc/shadow"])
 * The ls binary receives three arguments: ";", "cat", "/etc/shadow"
 * and treats them as filenames to list — not as shell commands to execute.
 *
 * NIST SP 800-53 Control Satisfied:
 *   SI-10 — Information Input Validation: input is tokenized into discrete
 *            argument strings; no shell interpolation occurs.
 *
 * CWE-78 remediation: replace system() with fork() + execvp().
 *
 * Compile: gcc -o safe_shell safe_shell.c
 * Run:     ./safe_shell
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define MAX_LINE 1024
#define MAX_ARGS 64

/* tokenize input into argv-style array — no shell interpolation */
int parse_args(char *line, char **args) {
    int count = 0;
    char *token = strtok(line, " \t");
    while (token != NULL && count < MAX_ARGS - 1) {
        args[count++] = token;
        token = strtok(NULL, " \t");
    }
    args[count] = NULL;
    return count;
}

int main(void) {
    char input[MAX_LINE];
    char *args[MAX_ARGS];

    printf("=== SAFE SHELL (uses execvp()) ===\n");
    printf("This shell is NOT vulnerable to command injection.\n");
    printf("Try: ls ; whoami   <- semicolon treated as literal filename\n");
    printf("Try: echo hello && cat /etc/passwd   <- && is a literal arg\n\n");

    while (1) {
        printf("safe$ ");
        fflush(stdout);

        if (fgets(input, MAX_LINE, stdin) == NULL) {
            printf("\n");
            break;
        }

        input[strcspn(input, "\n")] = '\0';

        if (strcmp(input, "exit") == 0)
            break;

        if (strlen(input) == 0)
            continue;

        int argc = parse_args(input, args);
        if (argc == 0)
            continue;

        pid_t pid = fork();
        if (pid == -1) {
            perror("fork");
            continue;
        }

        if (pid == 0) {
            /*
             * FIX: execvp() passes args directly to the kernel.
             * No shell is invoked. Metacharacters are inert.
             *
             * "ls ; whoami" becomes: execvp("ls", ["ls", ";", "whoami"])
             * ls receives ";" and "whoami" as filenames — not shell commands.
             */
            execvp(args[0], args);
            fprintf(stderr, "%s: command not found\n", args[0]);
            exit(EXIT_FAILURE);
        }

        int status;
        waitpid(pid, &status, 0);
    }

    return 0;
}
