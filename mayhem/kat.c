// Known-answer probe for the host-side verification library. Prints deterministic `key=value`
// lines that mayhem/test.sh compares with mayhem/kat.expected. Built with normal flags (no sanitizers).
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/tdx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/host_verify.h>
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "../common/sgx/endorsements.h"
#include "../common/sgx/tcbinfo.h"

static const char* root;
static FILE* out; /* results; the library traces to stdout, which is sent to /dev/null */

static uint8_t* slurp(const char* rel, size_t* n, int nul)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", root, rel);
    FILE* f = fopen(path, "rb");
    if (!f)
    {
        fprintf(stderr, "cannot open %s\n", path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t* b = malloc((size_t)len + 1);
    if (fread(b, 1, (size_t)len, f) != (size_t)len)
        exit(2);
    fclose(f);
    b[len] = 0;
    *n = (size_t)len + (nul ? 1 : 0);
    size_t skip = 0; /* fixtures may start with '#' licence-comment lines */
    while (skip < (size_t)len && b[skip] == '#')
    {
        while (skip < (size_t)len && b[skip] != '\n')
            skip++;
        skip++;
    }
    if (skip)
    {
        memmove(b, b + skip, (size_t)len - skip + 1);
        *n -= skip;
    }
    return b;
}

static void hex(const char* key, const uint8_t* p, size_t n)
{
    fprintf(out, "%s=", key);
    for (size_t i = 0; i < n; i++)
        fprintf(out, "%02x", p[i]);
    fprintf(out, "\n");
}

static void dt(const char* key, const oe_datetime_t* d)
{
    fprintf(out,
        "%s=%04u-%02u-%02uT%02u:%02u:%02uZ\n",
        key,
        d->year,
        d->month,
        d->day,
        d->hours,
        d->minutes,
        d->seconds);
}

static void res(const char* key, oe_result_t r)
{
    fprintf(out, "%s=%s\n", key, oe_result_str(r));
}

static void kat_sha256(void)
{
    OE_SHA256 h;
    oe_sha256_context_t c;
    oe_sha256_init(&c);
    oe_sha256_update(&c, "abc", 3);
    oe_sha256_final(&c, &h);
    hex("sha256.abc", h.buf, sizeof(h.buf));
}

static void kat_tcb(const char* tag, const char* rel)
{
    size_t n;
    uint8_t* json = slurp(rel, &n, 1);
    oe_tcb_info_tcb_level_t plat;
    oe_parsed_tcb_info_t p;
    char k[128];
    memset(&plat, 0xff, sizeof(plat));
    plat.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    memset(&p, 0, sizeof(p));
    oe_result_t r = oe_parse_tcb_info_json(json, n, &plat, &p);
    snprintf(k, sizeof(k), "tcb.%s.result", tag);
    res(k, r);
    if (r == OE_OK || r == OE_TCB_LEVEL_INVALID)
    {
        snprintf(k, sizeof(k), "tcb.%s.version", tag);
        fprintf(out, "%s=%u\n", k, p.version);
        if (p.version >= 2)
        {
            const oe_tcb_info_tcb_level_t* l = p.version == 3 ? &p.tcb_info_v3.tcb_level : &p.tcb_info_v2.tcb_level;
            snprintf(k, sizeof(k), "tcb.%s.tcbdate", tag);
            dt(k, &l->tcb_date);
        }
        const uint8_t* fmspc = p.version == 3 ? p.tcb_info_v3.fmspc : p.version == 2 ? p.tcb_info_v2.fmspc : p.tcb_info_v2.fmspc;
        snprintf(k, sizeof(k), "tcb.%s.fmspc", tag);
        hex(k, fmspc, 6);
        const oe_tcb_info_tcb_level_t* l = p.version == 3 ? &p.tcb_info_v3.tcb_level : &p.tcb_info_v2.tcb_level;
        snprintf(k, sizeof(k), "tcb.%s.sgxsvn", tag);
        hex(k, l->sgx_tcb_comp_svn, 16);
        snprintf(k, sizeof(k), "tcb.%s.pcesvn", tag);
        fprintf(out, "%s=%u\n", k, l->pce_svn);
        snprintf(k, sizeof(k), "tcb.%s.status", tag);
        fprintf(out, "%s=%u\n", k, l->status.AsUINT32);
        snprintf(k, sizeof(k), "tcb.%s.signature", tag);
        hex(k, p.signature, 8);
    }
    free(json);
}

static void kat_qe(const char* tag, const char* rel, uint32_t isvsvn)
{
    size_t n;
    uint8_t* json = slurp(rel, &n, 1);
    oe_qe_identity_info_tcb_level_t plat;
    oe_parsed_qe_identity_info_t p;
    char k[128];
    memset(&plat, 0, sizeof(plat));
    plat.isvsvn[0] = isvsvn;
    memset(&p, 0, sizeof(p));
    oe_result_t r = oe_parse_qe_identity_info_json(json, n, &plat, &p);
    snprintf(k, sizeof(k), "qe.%s.result", tag);
    res(k, r);
    if (r == OE_OK)
    {
        snprintf(k, sizeof(k), "qe.%s.version", tag);
        fprintf(out, "%s=%u\n", k, p.version);
        snprintf(k, sizeof(k), "qe.%s.isvprodid", tag);
        fprintf(out, "%s=%u\n", k, p.isvprodid);
        snprintf(k, sizeof(k), "qe.%s.isvsvn", tag);
        fprintf(out, "%s=%u\n", k, p.isvsvn);
        snprintf(k, sizeof(k), "qe.%s.miscselect", tag);
        fprintf(out, "%s=%08x/%08x\n", k, p.miscselect, p.miscselect_mask);
        snprintf(k, sizeof(k), "qe.%s.mrsigner", tag);
        hex(k, p.mrsigner, 32);
        snprintf(k, sizeof(k), "qe.%s.issue", tag);
        dt(k, &p.issue_date);
    }
    free(json);
}

static void kat_endorsements(void)
{
    size_t n;
    uint8_t* raw = slurp("tests/attestation_plugin/data/endorsements", &n, 0);
    oe_sgx_endorsements_t e;
    memset(&e, 0, sizeof(e));
    oe_result_t r = oe_parse_sgx_endorsements((const oe_endorsements_t*)raw, n, &e);
    res("endorsements.result", r);
    if (r == OE_OK)
        for (int i = 0; i < OE_SGX_ENDORSEMENT_COUNT; i++)
            fprintf(out, "endorsements.item%d.size=%u\n", i, e.items[i].size);
    free(raw);
}

static oe_result_t accept(oe_identity_t* id, void* arg)
{
    (void)id;
    (void)arg;
    return OE_OK;
}

static void kat_cert(const char* tag, const char* rel)
{
    size_t n;
    uint8_t* der = slurp(rel, &n, 0);
    oe_cert_t c;
    char k[128];
    oe_result_t r = oe_cert_read_der(&c, der, n);
    snprintf(k, sizeof(k), "cert.%s.read", tag);
    res(k, r);
    if (r == OE_OK)
    {
        oe_datetime_t from, until;
        if (oe_cert_get_validity_dates(&c, &from, &until) == OE_OK)
        {
            snprintf(k, sizeof(k), "cert.%s.notbefore", tag);
            dt(k, &from);
            snprintf(k, sizeof(k), "cert.%s.notafter", tag);
            dt(k, &until);
        }
        oe_parsed_extension_info_t info;
        memset(&info, 0, sizeof(info));
        snprintf(k, sizeof(k), "cert.%s.sgxext", tag);
        res(k, oe_parse_sgx_extensions(&c, &info));
        oe_cert_free(&c);
    }
    snprintf(k, sizeof(k), "cert.%s.attest", tag);
    res(k, oe_verify_attestation_certificate(der, n, accept, NULL));
    free(der);
}

static void kat_evidence(const char* tag, int tdx, const char* ev, const char* en)
{
    size_t evn, enn = 0;
    uint8_t* e = slurp(ev, &evn, 0);
    uint8_t* d = en ? slurp(en, &enn, 0) : NULL;
    static const oe_uuid_t sgx = {OE_FORMAT_UUID_SGX_ECDSA};
    static const oe_uuid_t tdxu = {OE_FORMAT_UUID_TDX_QUOTE_ECDSA};
    oe_claim_t* claims = NULL;
    size_t cl = 0;
    char k[128];
    oe_result_t r = oe_verify_evidence(tdx ? &tdxu : &sgx, e, evn, d, enn, NULL, 0, &claims, &cl);
    snprintf(k, sizeof(k), "evidence.%s.result", tag);
    if (tdx) /* TDX verdicts depend on Intel's QVL library being installed */
        fprintf(out, "%s=%s\n", k, r == OE_OK ? "accepted" : "rejected");
    else
        res(k, r);
    if (r == OE_OK)
    {
        snprintf(k, sizeof(k), "evidence.%s.claims", tag);
        fprintf(out, "%s=%zu\n", k, cl);
        oe_free_claims(claims, cl);
    }
    free(e);
    free(d);
}

int main(int argc, char** argv)
{
    root = argc > 1 ? argv[1] : ".";
    out = fdopen(dup(1), "w");
    dup2(fileno(tmpfile()), 1);
    if (oe_verifier_initialize() != OE_OK || oe_tdx_verifier_initialize() != OE_OK)
        return 3;
    kat_sha256();
    kat_tcb("v1", "tests/report/data/tcbInfo.json");
    kat_tcb("v2", "tests/report/data_v2/tcbInfo.json");
    kat_tcb("v2adv", "tests/report/data_v2/tcbInfoAdvisoryIds.json");
    kat_tcb("v3sgx", "tests/report/data_v3/tcbinfo_sgx.json");
    kat_tcb("v3tdx", "tests/report/data_v3/tcbinfo_tdx.json");
    kat_tcb("badfloat", "tests/report/data/tcbInfoNegativeFloat.json");
    kat_tcb("badlevel", "tests/report/data/tcbInfoNegativePropertyMissingLevel0.json");
    kat_qe("v1", "tests/qeidentity/data/qe_identity_ok.json", 2);
    kat_qe("v2", "tests/qeidentity/data_v2/qe_identity_ok.json", 2);
    kat_qe("qve", "tests/qeidentity/data_v2/qve_identity_ok.json", 2);
    kat_qe("nomrsigner", "tests/qeidentity/data/qe_identity_missing_mrsigner.json", 2);
    kat_endorsements();
    kat_cert("ec", "tests/host_verify/data/sgx_cert_ec_bad.der");
    kat_cert("rsa", "tests/host_verify/data/sgx_cert_rsa_bad.der");
    kat_evidence("sgx", 0, "tests/attestation_plugin/data/evidence", "tests/attestation_plugin/data/endorsements");
    kat_evidence("tdx", 1, "tests/host_verify/data/tdx_quote.bin", "tests/host_verify/data/tdx_endorsement.bin");
    fclose(out);
    return 0;
}
