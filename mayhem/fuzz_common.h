#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Heap copy of the fuzz input so ASan sees exact bounds; optionally NUL-terminated. */
static inline uint8_t* mayhem_copy(const uint8_t* d, size_t n, int nul)
{
    uint8_t* p = (uint8_t*)malloc(n + (nul ? 1 : 0) + 1);
    if (!p)
        abort();
    if (n)
        memcpy(p, d, n);
    if (nul)
        p[n] = 0;
    return p;
}
#endif
