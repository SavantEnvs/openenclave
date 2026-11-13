// Fuzzes oe_verify_evidence() for the SGX-ECDSA and TDX-ECDSA evidence formats.
// Input: [u8 format (bit0: 0=SGX,1=TDX)][u16 LE evidence_size][evidence][endorsements].
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/tdx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include "fuzz_common.h"

static const oe_uuid_t sgx_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
static const oe_uuid_t tdx_uuid = {OE_FORMAT_UUID_TDX_QUOTE_ECDSA};

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc;
    (void)argv;
    if (oe_verifier_initialize() != OE_OK || oe_tdx_verifier_initialize() != OE_OK)
        abort();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 3)
        return -1;
    const oe_uuid_t* fmt = (data[0] & 1) ? &tdx_uuid : &sgx_uuid;
    size_t esize = (size_t)data[1] | ((size_t)data[2] << 8);
    if (esize == 0 || esize > size - 3 || size - 3 - esize == 0)
        return -1;
    size_t csize = size - 3 - esize;

    uint8_t* evidence = mayhem_copy(data + 3, esize, 0);
    uint8_t* endorsements = mayhem_copy(data + 3 + esize, csize, 0);
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;
    if (oe_verify_evidence(
            fmt, evidence, esize, endorsements, csize, NULL, 0, &claims, &claims_length) ==
        OE_OK)
        oe_free_claims(claims, claims_length);
    free(evidence);
    free(endorsements);
    return 0;
}
