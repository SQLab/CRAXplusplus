// Copyright 2021-2022 Software Quality Laboratory, NYCU.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <s2e/s2e.h>

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define POC_BUF_SIZE 4096
#define LD_PRELOAD_PATH_MAX_SIZE 64

void usage(const char *prog_name) {
    printf("Usage: %s [options...] binary [binary_args...]\n", prog_name);
    printf("\n");
    printf("Program Options:\n");
    printf("  -n  --no-make-symbolic      Don't mark the input bytes as symbolic\n");
    printf("  -?  --help                  This message\n");
    printf("\n");
    printf("Copyright (C) 2021-2022 Software Quality Laboratory, NYCU.\n");
    printf("This is free software, see the source for copying conditions. There is no\n");
    printf("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE\n");
}

int main(int argc, char *argv[], char *envp[]) {
    bool should_make_symbolic = true;
    int opt;
    int n;
    int pipe_fd[2];
    char buf[POC_BUF_SIZE];
    char ld_preload[LD_PRELOAD_PATH_MAX_SIZE] = "LD_PRELOAD=";
    const char *ld_preload_value;

    struct option long_options[] = {
        {"help",             0, NULL, 'h'},
        {"no-make-symbolic", 0, NULL, 'n'},
        {0, 0, 0, 0}  // sentinel
    };

    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Parse command-line options.
    while ((opt = getopt_long(argc, argv, "h:n", long_options, NULL)) != EOF) {
        switch (opt) {
            case 'n':
                should_make_symbolic = false;
                break;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    puts("Give me crash input via stdin: ");
    n = read(0, buf, sizeof(buf));

    if (n < 0) {
        perror("payload error");
        return EXIT_FAILURE;
    }

    if (should_make_symbolic) {
        s2e_make_symbolic(buf, n, "CRAX");
    }

    if (pipe(pipe_fd) < 0) {
        perror("pipe error");
        return EXIT_FAILURE;
    }

    write(pipe_fd[1], buf, n);

    // Prepare the argv for execve().
    // The command-line arguments starts at `optind` (an extern int defined by getopt).
    size_t new_argc = argc - optind + 1;
    char *args[new_argc];
    int i;
    for (i = 0; i < new_argc; i++) {
        args[i] = argv[optind + i];
    }
    args[i] = NULL;

    // Prepare the envp for execve().
    ld_preload_value = getenv("LD_PRELOAD");
    if (ld_preload_value) {
       printf("[*] LD_PRELOAD=%s\n", ld_preload_value);
       strncat(ld_preload, ld_preload_value, sizeof(ld_preload) - strlen(ld_preload));
       ld_preload[LD_PRELOAD_PATH_MAX_SIZE - 1] = 0;
    }
    char *envs[] = {
        ld_preload
    };

    // Start the target program.
    pid_t pid;
    switch (pid = fork()) {
        case -1:
            perror("failed to fork child process");
            return EXIT_FAILURE;
        case 0:  // child
            dup2(pipe_fd[0], 0);
            close(pipe_fd[0]);
            close(pipe_fd[1]);
            execve(args[0], args, (ld_preload_value) ? envs : NULL);
            break;
        default:  // parent
            close(pipe_fd[0]);
            close(pipe_fd[1]);
            wait(NULL);
            s2e_kill_state(0, "program terminated");
            break;
    }

    return EXIT_SUCCESS;
}
