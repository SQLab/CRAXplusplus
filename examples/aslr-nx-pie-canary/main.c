#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    char buf[0x18];

    printf("what's your name: ");
    read(0, buf, 0x80);

    printf("%s\n", buf);
    read(0, buf, 0x80);

    printf("%sThanks for your feedback\n", buf);
    read(0, buf, 0x30);
}
