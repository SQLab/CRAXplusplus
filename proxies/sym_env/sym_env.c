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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define POC_NAME_SIZE 32
#define POC_VALUE_SIZE 4096
#define POC_BUF_SIZE (POC_NAME_SIZE + 1 + POC_VALUE_SIZE)

char name[POC_NAME_SIZE] = {0};
char value[POC_VALUE_SIZE] = {0};
char buf[POC_BUF_SIZE] = {0};

void usage(const char *prog_name) {
    printf("Usage: %s [options...] binary [binary_args...]\n", prog_name);
    printf("\n");
    printf("Copyright (C) 2021-2022 Software Quality Laboratory, NYCU.\n");
    printf("This is free software, see the source for copying conditions. There is no\n");
    printf("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE\n");
}

int main(int argc, char *argv[], char *envp[]) {
    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    puts("Give me env var name: ");
    fgets(name, POC_NAME_SIZE, stdin);
    name[strcspn(name, "\n")] = 0;

    puts("Give me env var value: ");
    fgets(value, POC_VALUE_SIZE, stdin);
    value[strcspn(value, "\n")] = 0;

    // Prepare the argv for execve().
    char *args[argc - 1];
    int i;
    for (i = 0; i < argc - 1; i++) {
        args[i] = argv[i + 1];
    }
    args[i] = NULL;

    // Prepare symbolic envp
    char *envs[] = { buf, NULL };
    strncat(buf, name, POC_NAME_SIZE);
    strcat(buf, "=");
    strncat(buf, value, POC_VALUE_SIZE);
    printf("%s\n", buf);

    int n = strnlen(buf, POC_BUF_SIZE);
    int value_begin_idx = strchr(buf, '=') - buf + 1;
    s2e_make_symbolic(buf + value_begin_idx, n - value_begin_idx, "CRAX");

    // Start the target program.
    pid_t pid;
    switch (pid = fork()) {
        case -1:
            perror("failed to fork child process");
            return EXIT_FAILURE;
        case 0:  // child
            execve(args[0], args, envs);
            break;
        default:  // parent
            wait(NULL);
            puts("terminating state");
            s2e_kill_state(0, "program terminated");
            break;
    }

    return EXIT_SUCCESS;
}
