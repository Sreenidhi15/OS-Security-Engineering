/*
 *
 * Compile: gcc -o myshell myshell.c audit_logger.c
 * Run:     ./myshell
 *
 * A basic Linux shell that supports pipelines, input/output
 * redirection, foreground and background execution.
 *
 * Security extension — Audit Logging (NIST SP 800-53: AU-2, AU-3, AU-12):
 *   Every command executed is recorded to shell_audit.log with:
 *   timestamp, real UID, PID, full command string, and exit status.
 *   This satisfies the audit event generation requirements of AU-12
 *   and produces records with the content fields required by AU-3.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "audit_logger.h"       /* AU-2 / AU-3 / AU-12 audit logging */

#define MAX_LINE 1024
#define MAX_ARGS 64
#define MAX_CMDS 16
#define AUDIT_LOG_FILE "shell_audit.log"

/* strips spaces/tabs/newlines from both ends of a string */
char *trim(char *str) {
    while (*str == ' ' || *str == '\t' || *str == '\n')
        str++;
    if (*str == '\0')
        return str;
    char *end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n'))
        end--;
    *(end + 1) = '\0';
    return str;
}

/* splits the command line at every '|' character manually,
   avoiding strtok so we don't mess up later parsing */
int split_by_pipe(char *line, char **cmds) {
    int count = 0;
    cmds[count++] = line;
    char *p = line;
    while (*p != '\0') {
        if (*p == '|') {
            *p = '\0';
            cmds[count++] = p + 1;
            if (count >= MAX_CMDS) break;
        }
        p++;
    }
    return count;
}

/* breaks a single sub-command into tokens (space/tab separated) */
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

/* looks for < or > in the string, pulls out the filename,
   and removes both the operator and filename from the original */
int find_and_remove_redir(char *str, char redir_ch, char *filename, int fnsize) {
    char *pos = strchr(str, redir_ch);
    if (pos == NULL)
        return 0;
    char *fn_start = pos + 1;
    while (*fn_start == ' ' || *fn_start == '\t')
        fn_start++;
    char *fn_end = fn_start;
    while (*fn_end && *fn_end != ' ' && *fn_end != '\t')
        fn_end++;
    int fn_len = fn_end - fn_start;
    if (fn_len <= 0 || fn_len >= fnsize)
        return 0;
    strncpy(filename, fn_start, fn_len);
    filename[fn_len] = '\0';
    memmove(pos, fn_end, strlen(fn_end) + 1);
    return 1;
}

/*
 * execute_command — parse and run a full command line.
 *
 * Returns the exit status of the last foreground command,
 * or -1 for background commands (exit status not collected).
 * The return value is passed directly to audit_log().
 */
int execute_command(char *line) {
    int background = 0;
    int len = strlen(line);
    int exit_status = -1;

    if (len > 0 && line[len - 1] == '&') {
        background = 1;
        line[len - 1] = '\0';
        line = trim(line);
    }

    char buf[MAX_LINE];
    strncpy(buf, line, MAX_LINE - 1);
    buf[MAX_LINE - 1] = '\0';

    char *cmds[MAX_CMDS];
    int num_cmds = split_by_pipe(buf, cmds);

    char input_file[MAX_LINE];
    int has_input = find_and_remove_redir(cmds[0], '<', input_file, MAX_LINE);

    char output_file[MAX_LINE];
    int has_output = find_and_remove_redir(cmds[num_cmds - 1], '>', output_file, MAX_LINE);

    char *args_array[MAX_CMDS][MAX_ARGS];
    int args_count[MAX_CMDS];
    int i;

    for (i = 0; i < num_cmds; i++) {
        char *trimmed = trim(cmds[i]);
        char tmp[MAX_LINE];
        strncpy(tmp, trimmed, MAX_LINE - 1);
        tmp[MAX_LINE - 1] = '\0';
        args_count[i] = parse_args(tmp, args_array[i]);
        int j;
        for (j = 0; j < args_count[i]; j++)
            args_array[i][j] = strdup(args_array[i][j]);
        args_array[i][args_count[i]] = NULL;
    }

    for (i = 0; i < num_cmds; i++) {
        if (args_count[i] == 0) {
            fprintf(stderr, "Error: empty command in pipeline\n");
            int ci, cj;
            for (ci = 0; ci < num_cmds; ci++)
                for (cj = 0; cj < args_count[ci]; cj++)
                    free(args_array[ci][cj]);
            return -1;
        }
    }

    int pipefds[MAX_CMDS - 1][2];
    for (i = 0; i < num_cmds - 1; i++) {
        if (pipe(pipefds[i]) == -1) {
            perror("pipe");
            return -1;
        }
    }

    pid_t pids[MAX_CMDS];
    for (i = 0; i < num_cmds; i++) {
        pids[i] = fork();
        if (pids[i] == -1) {
            perror("fork");
            return -1;
        }

        if (pids[i] == 0) {
            if (i == 0 && has_input) {
                int fd_in = open(input_file, O_RDONLY);
                if (fd_in == -1) {
                    fprintf(stderr, "%s: File not found\n", input_file);
                    exit(EXIT_FAILURE);
                }
                dup2(fd_in, STDIN_FILENO);
                close(fd_in);
            }

            if (i == num_cmds - 1 && has_output) {
                int fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd_out == -1) {
                    fprintf(stderr, "%s: Cannot create file\n", output_file);
                    exit(EXIT_FAILURE);
                }
                dup2(fd_out, STDOUT_FILENO);
                close(fd_out);
            }

            if (i > 0)
                dup2(pipefds[i - 1][0], STDIN_FILENO);
            if (i < num_cmds - 1)
                dup2(pipefds[i][1], STDOUT_FILENO);

            int k;
            for (k = 0; k < num_cmds - 1; k++) {
                close(pipefds[k][0]);
                close(pipefds[k][1]);
            }

            execvp(args_array[i][0], args_array[i]);
            fprintf(stderr, "%s: Command not found\n", args_array[i][0]);
            exit(EXIT_FAILURE);
        }
    }

    for (i = 0; i < num_cmds - 1; i++) {
        close(pipefds[i][0]);
        close(pipefds[i][1]);
    }

    if (background) {
        printf("[%d]\n", pids[num_cmds - 1]);
        exit_status = -1;   /* background: exit status not collected; logged as -1 */
    } else {
        int status;
        for (i = 0; i < num_cmds; i++) {
            waitpid(pids[i], &status, 0);
            /* capture exit status of the last command in the pipeline */
            if (i == num_cmds - 1) {
                exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            }
        }
    }

    int ci, cj;
    for (ci = 0; ci < num_cmds; ci++)
        for (cj = 0; cj < args_count[ci]; cj++)
            free(args_array[ci][cj]);

    return exit_status;
}

/* main loop */
int main(void) {
    char line[MAX_LINE];

    /* AU-12: initialize audit log at session start */
    if (audit_init(AUDIT_LOG_FILE) != 0) {
        fprintf(stderr, "Warning: audit logging unavailable. Continuing without audit trail.\n");
    }

    while (1) {
        printf("$ ");
        fflush(stdout);

        if (fgets(line, MAX_LINE, stdin) == NULL) {
            printf("\n");
            break;
        }

        char *trimmed = trim(line);
        if (strlen(trimmed) == 0)
            continue;

        if (strcmp(trimmed, "exit") == 0) {
            audit_log("exit", 0);   /* AU-2: log the exit event */
            break;
        }

        /* AU-12: execute command and capture exit status for the audit record */
        int exit_status = execute_command(trimmed);

        /* AU-3: write audit record with full command and exit status */
        audit_log(trimmed, exit_status);

        while (waitpid(-1, NULL, WNOHANG) > 0);
    }

    audit_close();  /* AU-12: write session end marker */
    return 0;
}
