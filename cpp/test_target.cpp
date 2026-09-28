// test_target.cpp - read file path argument, heap OOB by header length field
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 2) return 0;
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 0;
    unsigned char hdr[512];
    int n = (int)fread(hdr, 1, 512, f);
    fclose(f);
    if (n < 8) return 0;
    int count = *(int*)hdr;
    if (count < 0) count = -count;
    if (count > 100000) count = 100000;
    unsigned char* small = (unsigned char*)malloc(8);
    if (!small) return -1;
    memcpy(small, hdr, (size_t)count);   // heap OOB
    free(small);
    return 0;
}
