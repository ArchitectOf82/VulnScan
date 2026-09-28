// test_parse.cpp - DLL with an export parse_data(const unsigned char*, size_t)
// Heap OOB copy by a header length field. For fuzzer dll-mode verification.
#include <string.h>
#include <stdlib.h>

__declspec(dllexport) int parse_data(const unsigned char* buf, size_t len) {
    if (!buf || len < 8) return 0;
    int count = *(int*)buf;
    if (count < 0) count = -count;
    if (count > 100000) count = 100000;
    unsigned char* small = (unsigned char*)malloc(8);
    if (!small) return -1;
    memcpy(small, buf, (size_t)count);   // heap OOB
    free(small);
    return 0;
}
