// Fuzzes oe_verify_attestation_certificate(): X.509 DER with an embedded SGX quote extension.
#include <openenclave/host_verify.h>
#include "fuzz_common.h"

static oe_result_t accept_identity(oe_identity_t* identity, void* arg)
{
    (void)identity;
    (void)arg;
    return OE_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
        return -1;
    uint8_t* der = mayhem_copy(data, size, 0);
    (void)oe_verify_attestation_certificate(der, size, accept_identity, NULL);
    free(der);
    return 0;
}
