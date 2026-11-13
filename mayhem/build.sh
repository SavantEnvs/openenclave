#!/usr/bin/env bash
#
# mayhem/build.sh — build the Open Enclave host-side verification library (quote/report/evidence/
# collateral verification, crypto cert/CRL parsers) from source with clang, once with the sanitizers
# (fuzz + standalone binaries) and once with normal flags (the known-answer test probe).
# The full CMake build needs the SGX toolchain, so the library sources are compiled directly,
# exactly as host/CMakeLists.txt's oehostverify target lists them.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${COVERAGE_FLAGS=}"
: "${OEEDGER8R:=/opt/toolchains/deps/oeedger8r-cpp-420c5d5/bin/oeedger8r}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/build"
INC="$B/oe-include"
mkdir -p "$B/fuzz" "$B/normal" "$INC/openenclave/bits" "$INC/openenclave/internal/bits/sgx"

# 1) Untrusted-side headers generated from the EDL files (the same step upstream's CMake runs).
gen() {
  local edl="$1" out="$2" n; n="$(basename "$edl" .edl)"
  local t; t="$(mktemp -d)"
  (cd "$t" && "$OEEDGER8R" --header-only --untrusted "$SRC/$edl" >/dev/null && cp "${n}_args.h" "$out/$n.h")
  rm -rf "$t"
}
for e in asym_keys time; do gen "include/openenclave/edl/$e.edl" "$INC/openenclave/bits"; done
for e in fcntl poll socket utsname; do gen "include/openenclave/edl/$e.edl" "$INC/openenclave/internal/bits"; done
gen include/openenclave/edl/sgx/switchless.edl "$INC/openenclave/internal/bits/sgx"

# 2) The library: sources of the oehostverify target.
SRCS="common/attest_plugin.c common/custom_claims.c common/datetime.c common/safecrt.c common/sha.c
host/memalign.c host/hexdump.c host/dupenv.c host/fopen.c host/tests.c host/result.c host/traceh.c
common/cert.c common/crypto/openssl/asn1.c common/crypto/openssl/cert.c common/crypto/openssl/crl.c
common/crypto/openssl/ec.c common/crypto/openssl/key.c common/crypto/openssl/rsa.c common/crypto/openssl/sha.c
host/crypto/openssl/init.c host/crypto/openssl/rsa.c host/linux/hostthread.c host/linux/time.c
common/sgx/endorsements.c common/sgx/qeidentity.c common/sgx/quote.c common/sgx/report.c
common/sgx/report_helper.c common/sgx/collateral.c common/sgx/sgxcertextensions.c common/sgx/sgxmeasure.c
common/sgx/tcbinfo.c common/sgx/tlsverifier.c common/sgx/verifier.c common/tdx/quote.c common/tdx/verifier.c
host/sgx/hostverify_report.c host/sgx/report_common.c host/sgx/sgxquoteprovider.c host/sgx/quote.c
host/sgx/sgxquote.c host/tdx/quote.c host/sgx/linux/sgxquoteexloader.c host/strings.c host/sgx/elf.c host/sgx/loadelf.c mayhem/sgxload_stub.c
mayhem/quote_provider_stub.c"

DEFS=(-DOE_BUILD_HOST_VERIFY -DOE_BUILD_UNTRUSTED -DOE_API_VERSION=2 -D_GNU_SOURCE
      '-DOE_REPO_BRANCH_NAME="mayhem"' '-DOE_REPO_LAST_COMMIT="mayhem"')
INCS=(-I"$SRC/include" -I"$INC" -I"$SRC/3rdparty/sgxsdk/include" -I"$SRC/host" -I"$SRC/host/sgx")
WARN=(-fPIC -w)

build_lib() { # <outdir> <compiler + flags...>
  local out="$1"; shift
  local fail=0 s
  rm -f "$out"/*.o "$out/liboehv.a"
  for s in $SRCS; do
    while [ "$(jobs -rp | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n || fail=1; done
    "$@" -c "$SRC/$s" -o "$out/$(echo "$s" | tr / _).o" &
  done
  while [ "$(jobs -rp | wc -l)" -gt 0 ]; do wait -n || fail=1; done
  [ "$fail" -eq 0 ] || { echo "library compile failed" >&2; exit 1; }
  ar rcs "$out/liboehv.a" "$out"/*.o
}

build_lib "$B/fuzz" "$CC" $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 "${DEFS[@]}" "${INCS[@]}" "${WARN[@]}"
build_lib "$B/normal" "$CC" -O1 $COVERAGE_FLAGS "${DEFS[@]}" "${INCS[@]}" "${WARN[@]}"

LIBS=(-lssl -lcrypto -ldl -lpthread -lm)

# 3) Fuzz + standalone binaries (sanitized, DWARF 3, LSan hook linked in).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/sancov_stub.c" -o "$B/sancov_stub.o"

TARGETS="fuzz_sgx_report fuzz_evidence fuzz_tcb_info fuzz_qe_identity fuzz_endorsements fuzz_attestation_cert fuzz_custom_claims fuzz_crypto fuzz_elf_loader"
for t in $TARGETS; do
  HF=("$SRC/mayhem/$t.c" "${DEFS[@]}" "${INCS[@]}" -I"$SRC/mayhem" "${WARN[@]}")
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 $LIB_FUZZING_ENGINE "${HF[@]}" "$B/lsan_off.o" "$B/fuzz/liboehv.a" "${LIBS[@]}" -o "$SRC/$t"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${HF[@]}" "$B/standalone_main.o" "$B/sancov_stub.o" "$B/lsan_off.o" "$B/fuzz/liboehv.a" "${LIBS[@]}" -o "$SRC/$t-standalone"
done

# 4) Test oracle probe: normal flags, no sanitizers.
$CC -O1 $COVERAGE_FLAGS "${DEFS[@]}" "${INCS[@]}" -I"$SRC/mayhem" "${WARN[@]}" "$SRC/mayhem/kat.c" "$B/normal/liboehv.a" "${LIBS[@]}" -o "$SRC/oe_kat"
