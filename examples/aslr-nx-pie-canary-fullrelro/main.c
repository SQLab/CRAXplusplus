#include <stdio.h>
#include <unistd.h>

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
}
