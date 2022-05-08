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

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

void usage(const char *prog_name) {
    printf("Usage: %s sym_file [options...] binary [binary_args...]\n", prog_name);
    printf("\n");
    printf("Copyright (C) 2021-2022 Software Quality Laboratory, NYCU.\n");
    printf("This is free software, see the source for copying conditions. There is no\n");
    printf("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE\n");
}

int main(int argc, char *argv[], char *envp[]) {
    int fd;
    void *p;

    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    fd = open(argv[optind], O_RDWR);

    if (fd < 0) {
        perror("open file error\n");
        return EXIT_FAILURE;
    }

    struct stat b;

    if (fstat(fd, &b) == -1) {
        perror("fstat error\n");
        return EXIT_FAILURE;
    }

    p = mmap(0, b.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    
    if (p == (void *) -1) {
        perror("mmap error\n");
        return EXIT_FAILURE;
    }
    
    s2e_make_symbolic(p, b.st_size, "CRAX");

    // Prepare the argv for execve().
    char *args[argc - 1];
    int i;
    for (i = 0; i < argc - 1; i++) {
        args[i] = argv[i + 1];
    }
    args[i] = NULL;

    // Start the target program.
    pid_t pid;
    switch (pid = fork()) {
        case -1:
            perror("failed to fork child process");
            return EXIT_FAILURE;
        case 0:  // child
            execve(args[0], args, NULL);
            break;
        default:  // parent
            wait(NULL);
            s2e_kill_state(0, "program terminated");
            break;
    }

    return EXIT_SUCCESS;
}
