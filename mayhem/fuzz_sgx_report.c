// Fuzzes oe_verify_remote_report(): SGX ECDSA quote + collateral parsing/verification.
// Input: [u16 LE report_size][report][endorsements].
#include <openenclave/host_verify.h>
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 2)
        return -1;
    size_t rsize = (size_t)data[0] | ((size_t)data[1] << 8);
    if (rsize == 0 || rsize > size - 2 || size - 2 - rsize == 0)
        return -1;
    size_t esize = size - 2 - rsize;

    uint8_t* report = mayhem_copy(data + 2, rsize, 0);
    uint8_t* endorsements = mayhem_copy(data + 2 + rsize, esize, 0);
    oe_report_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    (void)oe_verify_remote_report(report, rsize, endorsements, esize, &parsed);
    free(report);
    free(endorsements);
    return 0;
}
