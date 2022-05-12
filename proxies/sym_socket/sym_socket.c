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

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define POC_BUF_SIZE 4096

char buf[POC_BUF_SIZE] = {0};

void usage(const char *prog_name) {
    printf("Usage: %s [options...] binary [binary_args...]\n", prog_name);
    printf("\n");
    printf("Copyright (C) 2021-2022 Software Quality Laboratory, NYCU.\n");
    printf("This is free software, see the source for copying conditions. There is no\n");
    printf("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE\n");
}


// Currently, this proxy only supports IPv6.
// TODO: Add ipv4 support.
int main(int argc, char *argv[], char *envp[]) {
    const char *addr = NULL;
    int port = 0;
    int n = 0;
    int fd = -1;
    struct sockaddr_in6 serv_addr;

    if (argc < 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    addr = argv[1];
    port = atoi(argv[2]);

    if (!port) {
        printf("Invalid port provided\n");
        return EXIT_FAILURE;
    }

    puts("Give me crash input, and I'll send it to the server: ");
    n = read(0, buf, sizeof(buf));

    s2e_make_symbolic(buf, n, "CRAX");

    if ((fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        puts("Socket init error");
        return -1;
    }

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_port = htons(port);
 
    // Convert IPv6 addresses from text to binary form
    if (inet_pton(AF_INET6, addr, &serv_addr.sin6_addr) != 1) {
        puts("inet_pton() failed");
        return -1;
    }
 
    if (sendto(fd, buf, n, 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr))
        == -1) {
        puts("Could not send (full) payload");
        return -1;
    }

    //s2e_kill_state(0, "program terminated");

    puts("Sent payload");
    close(fd);
    return EXIT_SUCCESS;
}
