// test_stdin.cpp - read from STDIN, heap OOB by header length field
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    unsigned char buf[1024];
    size_t n = 0;
    int c;
    while ((c = fgetc(stdin)) != EOF && n < sizeof buf) buf[n++] = (unsigned char)c;
    if (n < 8) return 0;
    int count = *(int*)buf;
    if (count < 0) count = -count;
    if (count > 100000) count = 100000;
    unsigned char* small = (unsigned char*)malloc(8);
    if (!small) return -1;
    memcpy(small, buf, (size_t)count);   // heap OOB
    free(small);
    return 0;
}
