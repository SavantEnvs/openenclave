// Stand-in for host/sgx/linux/sgxquoteproviderloader.c. The upstream loader dlopen()s Intel's
// libdcap_quoteprov.so, which fetches collateral from a PCCS over the network. Neither exists in the
// fuzzing environment, and without a provider oe_verifier_initialize() refuses to start. This stub
// registers a provider whose collateral lookup always reports "no data", like an unreachable PCCS, so the
// verifier code under test runs unchanged.
#include <openenclave/internal/trace.h>
#include <stdint.h>
#include <stdlib.h>
#include "../host/sgx/sgxquoteprovider.h"
#include "openenclave/bits/result.h"

static sgx_plat_error_t no_collateral(
    const uint8_t* fmspc,
    const uint16_t fmspc_size,
    const char* pck_ca,
    sgx_ql_qve_collateral_t** pp_qve_collateral)
{
    (void)fmspc;
    (void)fmspc_size;
    (void)pck_ca;
    *pp_qve_collateral = NULL;
    return SGX_PLAT_NO_DATA_FOUND;
}

static sgx_plat_error_t free_collateral(sgx_ql_qve_collateral_t* collateral)
{
    (void)collateral;
    return SGX_PLAT_ERROR_OK;
}

static char provider_token;

oe_sgx_quote_provider_t provider = {0};

void oe_load_quote_provider(void)
{
    provider.handle = &provider_token;
    provider.get_sgx_quote_verification_collateral = no_collateral;
    provider.free_sgx_quote_verification_collateral = free_collateral;
}

oe_result_t oe_sgx_set_quote_provider_logger(sgx_ql_logging_function_t logger)
{
    (void)logger;
    return OE_UNSUPPORTED;
}
