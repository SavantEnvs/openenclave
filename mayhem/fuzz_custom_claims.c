// Fuzzes the serialized custom-claims buffer decoder.
#include <openenclave/attestation/custom_claims.h>
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
        return -1;
    uint8_t* buf = mayhem_copy(data, size, 0);
    oe_claim_t* claims = NULL;
    size_t length = 0;
    if (oe_deserialize_custom_claims(buf, size, &claims, &length) == OE_OK)
        oe_free_custom_claims(claims, length);
    free(buf);
    return 0;
}
