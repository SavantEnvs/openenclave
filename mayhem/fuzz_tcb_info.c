// Fuzzes the Intel PCS TCB-info JSON parser (SGX/TDX collateral).
// Input: [u8 variant (bit0: with/without pce svn)][json text].
#include <openenclave/internal/sgxcertextensions.h>
#include "../common/sgx/tcbinfo.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 2)
        return -1;
    uint8_t* json = mayhem_copy(data + 1, size - 1, 1);
    oe_tcb_info_tcb_level_t level;
    oe_parsed_tcb_info_t parsed;
    memset(&level, 0, sizeof(level));
    memset(&parsed, 0, sizeof(parsed));
    if (data[0] & 1)
        (void)oe_parse_tcb_info_json_without_pce_svn(json, size, &level, &parsed);
    else
        (void)oe_parse_tcb_info_json(json, size, &level, &parsed);
    free(json);
    return 0;
}
