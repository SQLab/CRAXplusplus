#include <unistd.h>

int main() {
    char buf[0x8];
    read(0, buf, 0x50);
}
