// Fuzzes the host crypto parsers: X.509 PEM/DER, PEM chains, CRLs, EC public keys, SGX cert extensions.
// Input: [u8 selector][payload].
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/crypto/crl.h>
#include <openenclave/internal/crypto/ec.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/sgxcertextensions.h>
#include "fuzz_common.h"

static void use_cert(oe_cert_t* cert, int sgx_ext)
{
    oe_datetime_t from, until;
    oe_ec_public_key_t key;
    (void)oe_cert_get_validity_dates(cert, &from, &until);
    if (oe_cert_get_ec_public_key(cert, &key) == OE_OK)
        oe_ec_public_key_free(&key);
    if (sgx_ext)
    {
        oe_parsed_extension_info_t info;
        (void)oe_parse_sgx_extensions(cert, &info);
    }
    oe_cert_free(cert);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 2)
        return -1;
    int sel = data[0] % 6;
    size_t n = size - 1;
    int nul = (sel == 0 || sel == 2 || sel == 4 || sel == 5);
    uint8_t* p = mayhem_copy(data + 1, n, nul);
    size_t pn = nul ? n + 1 : n;

    switch (sel)
    {
        case 0:
        {
            oe_cert_t c;
            if (oe_cert_read_pem(&c, p, pn) == OE_OK)
                use_cert(&c, 1);
            break;
        }
        case 1:
        {
            oe_cert_t c;
            if (oe_cert_read_der(&c, p, pn) == OE_OK)
                use_cert(&c, 1);
            break;
        }
        case 2:
        {
            oe_cert_chain_t chain;
            if (oe_cert_chain_read_pem(&chain, p, pn) == OE_OK)
            {
                size_t len = 0;
                oe_cert_t leaf, root;
                (void)oe_cert_chain_get_length(&chain, &len);
                if (oe_cert_chain_get_leaf_cert(&chain, &leaf) == OE_OK)
                    oe_cert_free(&leaf);
                if (oe_cert_chain_get_root_cert(&chain, &root) == OE_OK)
                    oe_cert_free(&root);
                oe_cert_chain_free(&chain);
            }
            break;
        }
        case 3:
        {
            oe_crl_t crl;
            if (oe_crl_read_der(&crl, p, pn) == OE_OK)
                oe_crl_free(&crl);
            break;
        }
        case 4:
        {
            oe_crl_t crl;
            if (oe_crl_read_pem(&crl, p, pn) == OE_OK)
                oe_crl_free(&crl);
            break;
        }
        default:
        {
            oe_ec_public_key_t key;
            if (oe_ec_public_key_read_pem(&key, p, pn) == OE_OK)
                oe_ec_public_key_free(&key);
            break;
        }
    }
    free(p);
    return 0;
}
