#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer oracle for the Open Enclave host verification library.
# Runs the pre-built probe (/mayhem/oe_kat, normal flags) over the repo's own test vectors and compares
# every `key=value` line with mayhem/kat.expected (SHA-256 KAT, TCB-info / QE-identity JSON parsing,
# endorsements container, X.509 + SGX extension parsing, attestation-certificate and quote verification
# verdicts). Each expected line is one test.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

[ -x "$SRC/oe_kat" ] || { echo "oe_kat missing: mayhem/build.sh did not build it" >&2; emit_ctrf oe-kat 0 1 0; exit 1; }

actual="$(mktemp)"
"$SRC/oe_kat" "$SRC" > "$actual" 2> /dev/null

passed=0; failed=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  if grep -qxF -- "$line" "$actual"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1)); echo "FAIL: expected line missing: $line" >&2
  fi
done < "$SRC/mayhem/kat.expected"

# No extra, unexpected output either.
extra="$(grep -vxFf "$SRC/mayhem/kat.expected" "$actual" || true)"
if [ -n "$extra" ]; then
  failed=$((failed + 1)); echo "FAIL: unexpected probe output:" >&2; echo "$extra" >&2
fi
rm -f "$actual"
[ "$passed" -gt 0 ] || { echo "no expected lines found in mayhem/kat.expected" >&2; failed=$((failed + 1)); }
emit_ctrf oe-kat "$passed" "$failed" 0
