#include <stdio.h>
#include <string.h>
#include <unistd.h>

const char *msg = "hello!\n";

int main() {
    char buf[0x10] = {};

    write(1, msg, strlen(msg));
    read(0, buf, 0x40);
    printf("%s\n", buf);
    read(0, buf, 0x400);

    return 0;
}
