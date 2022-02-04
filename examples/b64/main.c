#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//#include <s2e/s2e.h>

const char *b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
size_t nr_bytes_read;
char encoded[0x400] = {};
char decoded[0x400] = {};

void b64encode(char *out, const char *in, size_t in_len) {
    size_t out_idx = 0;
    int val = 0;
    int valb = -6;

    for (size_t i = 0; i < in_len; i++) {
        val = (val << 8) + in[i];
        valb += 8;
        while (valb >= 0) {
            out[out_idx++] = b[(val >> valb) & 0x3F];
            valb -= 6;
        }
    }

    if (valb > -6) {
        out[out_idx++] = b[((val << 8) >> (valb + 8)) & 0x3F];
    }

    while (out_idx % 4) {
        out[out_idx++] = '=';
    }
}

void b64decode(char *out, const char *in, size_t in_len) {
    size_t out_idx = 0;

    int T[256];
    for (int i = 0; i < 256; i++) {
        T[i] = -1;
    }

    for (int i = 0; i < 64; i++) {
        T[b[i]] = i;
    }

    //s2e_make_symbolic(T, 256, "b64_T");

    int val = 0;
    int valb = -8;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (T[c] == -1) {
            break;
        }
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out[out_idx++] = ((char) (val >> valb)) & 0xff;
            valb -= 8;
        }
    }
}

int main() {
    char buf[8];
    printf("Give me some bytes to b64decode:\n");

    nr_bytes_read = read(0, encoded, 0x400);
    nr_bytes_read--;
    encoded[nr_bytes_read] = 0;
    b64decode(decoded, encoded, 0x400);
    memcpy(buf, decoded, 0x400);
}
