/*
 * EECE7376: Operating Systems - Course Project Part 1: Shell
 * name1: Akash Kotagi, name2: Sreenidhi Ramani
 * NUID1: 002586968, NUID2: 002592745
 *
 * Compile: gcc -o myshell myshell.c
 * Run:     ./myshell
 *
 * A basic Linux shell that supports pipelines, input/output
 * redirection, foreground and background execution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#define MAX_LINE 1024
#define MAX_ARGS 64
#define MAX_CMDS 16

/* strips spaces/tabs/newlines from both ends of a string */
char *trim(char *str) {
    while (*str == ' ' || *str == '\t' || *str == '\n')
        str++;
    if (*str == '\0')
        return str;

    char *end = str + strlen(str) - 1; /* start from the back */
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
            *p = '\0'; /* cut the string here */
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
    args[count] = NULL; /* execvp needs a NULL at the end */
    return count;
}

/* looks for < or > in the string, pulls out the filename,
   and removes both the operator and filename from the original */
int find_and_remove_redir(char *str, char redir_ch, char *filename, int fnsize) {
    char *pos = strchr(str, redir_ch);
    if (pos == NULL)
        return 0;

    char *fn_start = pos + 1; /* skip past the < or > */
    while (*fn_start == ' ' || *fn_start == '\t')
        fn_start++;

    char *fn_end = fn_start; /* walk to end of the filename */
    while (*fn_end && *fn_end != ' ' && *fn_end != '\t')
        fn_end++;

    int fn_len = fn_end - fn_start;
    if (fn_len <= 0 || fn_len >= fnsize)
        return 0;

    strncpy(filename, fn_start, fn_len);
    filename[fn_len] = '\0';

    memmove(pos, fn_end, strlen(fn_end) + 1); /* erase the redir part from the string */
    return 1;
}

/* this is the main workhorse - takes a full command line,
   figures out pipes/redirection/background, then forks and execs */
void execute_command(char *line) {
    int background = 0;
    int len = strlen(line);

    /* check if the user wants this running in the background */
    if (len > 0 && line[len - 1] == '&') {
        background = 1;
        line[len - 1] = '\0';
        line = trim(line);
    }

    char buf[MAX_LINE];
    strncpy(buf, line, MAX_LINE - 1);
    buf[MAX_LINE - 1] = '\0';

    /* break the line into sub-commands at each pipe */
    char *cmds[MAX_CMDS];
    int num_cmds = split_by_pipe(buf, cmds);

    /* pull out input redir from first cmd, output redir from last cmd */
    char input_file[MAX_LINE];
    int has_input = find_and_remove_redir(cmds[0], '<', input_file, MAX_LINE);

    char output_file[MAX_LINE];
    int has_output = find_and_remove_redir(cmds[num_cmds - 1], '>', output_file, MAX_LINE);

    /* now tokenize each sub-command into its own args array */
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
            args_array[i][j] = strdup(args_array[i][j]); /* need stable copies */
        args_array[i][args_count[i]] = NULL;
    }

    /* make sure none of the sub-commands ended up empty */
    for (i = 0; i < num_cmds; i++) {
        if (args_count[i] == 0) {
            fprintf(stderr, "Error: empty command in pipeline\n");
            int ci, cj;
            for (ci = 0; ci < num_cmds; ci++)
                for (cj = 0; cj < args_count[ci]; cj++)
                    free(args_array[ci][cj]);
            return;
        }
    }

    /* set up one pipe between each pair of adjacent sub-commands */
    int pipefds[MAX_CMDS - 1][2];
    for (i = 0; i < num_cmds - 1; i++) {
        if (pipe(pipefds[i]) == -1) {
            perror("pipe");
            return;
        }
    }

    /* fork a child for every sub-command in the pipeline */
    pid_t pids[MAX_CMDS];

    for (i = 0; i < num_cmds; i++) {
        pids[i] = fork();
        if (pids[i] == -1) {
            perror("fork");
            return;
        }

        if (pids[i] == 0) { /* we're in the child now */

            /* if this is the first command and there's an input file, redirect stdin */
            if (i == 0 && has_input) {
                int fd_in = open(input_file, O_RDONLY);
                if (fd_in == -1) {
                    fprintf(stderr, "%s: File not found\n", input_file);
                    exit(EXIT_FAILURE);
                }
                dup2(fd_in, STDIN_FILENO);
                close(fd_in);
            }

            /* if this is the last command and there's an output file, redirect stdout */
            if (i == num_cmds - 1 && has_output) {
                int fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd_out == -1) {
                    fprintf(stderr, "%s: Cannot create file\n", output_file);
                    exit(EXIT_FAILURE);
                }
                dup2(fd_out, STDOUT_FILENO);
                close(fd_out);
            }

            if (i > 0) /* read from the previous pipe if not the first cmd */
                dup2(pipefds[i - 1][0], STDIN_FILENO);

            if (i < num_cmds - 1) /* write to the next pipe if not the last cmd */
                dup2(pipefds[i][1], STDOUT_FILENO);

            /* close all pipe fds since we already dup'd what we need */
            int k;
            for (k = 0; k < num_cmds - 1; k++) {
                close(pipefds[k][0]);
                close(pipefds[k][1]);
            }

            execvp(args_array[i][0], args_array[i]); /* run the actual command */
            fprintf(stderr, "%s: Command not found\n", args_array[i][0]);
            exit(EXIT_FAILURE);
        }
    }

    /* parent closes all pipe fds - kids already have their own copies */
    for (i = 0; i < num_cmds - 1; i++) {
        close(pipefds[i][0]);
        close(pipefds[i][1]);
    }

    if (background) {
        printf("[%d]\n", pids[num_cmds - 1]); /* just print the pid and move on */
    } else {
        for (i = 0; i < num_cmds; i++) /* wait for all children to finish */
            waitpid(pids[i], NULL, 0);
    }

    /* free all the strdup'd argument strings */
    for (i = 0; i < num_cmds; i++) {
        int j;
        for (j = 0; j < args_count[i]; j++)
            free(args_array[i][j]);
    }
}

/* main loop - just keeps reading commands until the user exits */
int main(void) {
    char line[MAX_LINE];

    while (1) {
        printf("$ ");
        fflush(stdout);

        if (fgets(line, MAX_LINE, stdin) == NULL) { /* ctrl+d or end of input */
            printf("\n");
            break;
        }

        char *trimmed = trim(line);

        if (strlen(trimmed) == 0) /* blank line, just show prompt again */
            continue;

        if (strcmp(trimmed, "exit") == 0)
            break;

        execute_command(trimmed);

        while (waitpid(-1, NULL, WNOHANG) > 0); /* clean up any background zombies */
    }

    return 0;
}
