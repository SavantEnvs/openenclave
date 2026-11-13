// host/sgx/sgxload.c talks to the SGX driver (ioctl on /dev/sgx_enclave) and is irrelevant to parsing an
// enclave image. loadelf.c references oe_sgx_load_enclave_data() only from its page-adding callback, which
// the ELF-loader harness never invokes, so a stub that reports "unsupported" satisfies the linker.
#include <openenclave/bits/result.h>
#include <openenclave/internal/load.h>
#include <stdbool.h>
#include <stdint.h>
#include "../host/sgx/sgxload.h"

oe_result_t oe_sgx_load_enclave_data(
    oe_sgx_load_context_t* context,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend)
{
    (void)context;
    (void)base;
    (void)addr;
    (void)src;
    (void)flags;
    (void)extend;
    return OE_UNSUPPORTED;
}
