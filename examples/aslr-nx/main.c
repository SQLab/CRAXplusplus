#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setvbuf(stdout, 0, _IONBF, 0);

    char buf[0x20];
    printf("overflow me:");
    read(0, buf, 0x400);
}
