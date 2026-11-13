// Fuzzes the SGX endorsements container parser (oe_endorsements_t offset table).
#include <openenclave/bits/attestation.h>
#include "../common/sgx/endorsements.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Only sizes below the first 4-byte field (version) are rejected: libFuzzer's initial 1-byte input would
     * otherwise abort before the fuzzer iterates (fuzz-smoke). Truncated headers of 4..15 bytes still reach
     * the parser, which reads enclave_type/buffer_size/num_elements without checking endorsements_size. */
    if (size < sizeof(uint32_t))
        return -1;
    uint8_t* buf = mayhem_copy(data, size, 0);
    oe_sgx_endorsements_t out;
    memset(&out, 0, sizeof(out));
    (void)oe_parse_sgx_endorsements((const oe_endorsements_t*)buf, size, &out);
    free(buf);
    return 0;
}
