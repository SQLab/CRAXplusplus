#include <stdio.h>
#include <unistd.h>

int main() {
    char buf[0x10];
    read(0, buf, 0x80);
    printf("%s\n", buf);
    read(0, buf, 0x80);
}
