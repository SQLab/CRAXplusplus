// Copyright (C) 2021-2022, Marco Wang
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

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
}
#include <iostream>
#include <cstdlib>

#define DIE(msg)          \
    do {                  \
        std::perror(msg); \
        std::exit(1);     \
    } while (0)


int main(int argc, char *argv[]) {
    int n;
    char buf[1024];

    if (argc < 2) {
        puts("usage: ./symio program_path [args]");
        return EXIT_SUCCESS;
    }

    puts("Give me crash input via stdin: ");
    n = read(0, buf, sizeof(buf));
    if (n < 0) {
        perror("payload error");
        return EXIT_FAILURE;
    }
    s2e_make_symbolic(buf, n, "CRAX");
   
    int pipe_fd[2];
    if (pipe(pipe_fd) < 0) {
        DIE("pipe error");
    }
    write(pipe_fd[1], buf, n);

    char *args[argc - 1];
    int i;
    for (i = 0; i < argc - 1; i++) {
        args[i] = argv[i + 1];
    }
    args[i] = nullptr;

    pid_t pid;
    switch (pid = fork()) {
        case -1:
            DIE("failed to fork child process");
            break;
        case 0:  // child
            dup2(pipe_fd[0], 0);
            close(pipe_fd[0]);
            close(pipe_fd[1]);
            execve(args[0], args, nullptr);
            break;
        default:  // parent
            close(pipe_fd[0]);
            close(pipe_fd[1]);
            wait(nullptr);
            s2e_kill_state(0, "program terminated");
            break;
    }

    return EXIT_SUCCESS;
}
