#include <stdio.h>
#include <unistd.h>

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    char buf[0x20] = {0};
    printf("what's your name: ");
    read(0, buf, 0x80);

    printf("Hello, %s. Your comment: ", buf);
    read(0, buf, 0x80);

    printf("Thanks! We've received it: %s\n", buf);
    read(0, buf, 0x30);
}
