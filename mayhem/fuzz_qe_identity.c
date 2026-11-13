// Fuzzes the Intel PCS QE/QVE identity JSON parser (SGX collateral).
#include "../common/sgx/tcbinfo.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
        return -1;
    uint8_t* json = mayhem_copy(data, size, 1);
    oe_qe_identity_info_tcb_level_t level;
    oe_parsed_qe_identity_info_t parsed;
    memset(&level, 0, sizeof(level));
    memset(&parsed, 0, sizeof(parsed));
    (void)oe_parse_qe_identity_info_json(json, size + 1, &level, &parsed);
    free(json);
    return 0;
}
