#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <algorithm>

int main() {
    char buf[0x18];

    printf("what's your name: ");
    fflush(stdout);
    read(0, buf, 0x80);

    printf("Hello, %s. Your comment: ", buf);
    fflush(stdout);
    read(0, buf, 0x80);

    printf("Thanks! We've received it: %s\n", buf);
    fflush(stdout);
    read(0, buf, 0x30);

    std::reverse(buf, buf + 0x30);
    for (int i = 0; i < 0x30; i += 2) {
        buf[i] += 1;
    }
    for (int i = 1; i < 0x30; i+= 2) {
        buf[i] -= 3;
    }
}
