#!/usr/bin/env bash
#
# mayhem/test.sh — behavioral oracle for the migtd Mayhem integration.
#
# Layer: UNCONDITIONAL KAT probes. Run the dynamically-linked mayhem/kat probe
# (built by build.sh) on FIXED inputs and grep its EXACT output values from bash
# (bash/coreutils are whitelisted by the sabotage shim, so the compare happens where
# sabotage cannot hide). A missing binary or wrong/absent output = FAIL, never a skip.
#
# The probe drives the SAME parser surfaces the fuzz targets exercise:
#   * migration-policy: policy::MigPolicy via serde_json  (the `policy` target)
#   * X.509 DER decode: crypto::x509::Certificate::from_der (the `x509` target)
#
# `cargo test` is deliberately NOT used here: it links a STATICALLY-linked test
# binary that LD_PRELOAD cannot reach, so it would survive the sabotage neuter and
# prove nothing (SPEC §6.3 trap). The KAT probe is dynamically linked and drives the
# real parsers, so neutering them breaks it.
#
# Emits a CTRF summary + a compact `CTRF {...}` stdout line; exit 0 iff failed==0.
# Does NOT compile anything (build.sh did that).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

KAT_PASS=0
KAT_FAIL=0

# ── KAT probes (UNCONDITIONAL — a missing probe is a FAILURE, never a skip) ──────
KAT_BIN="$SRC/mayhem/kat/target/release/migtd-kat"
KAT_OUT="$("$KAT_BIN" 2>&1)" || KAT_OUT="${KAT_OUT:-<probe did not run>}"
echo "--- KAT probe output ---"
echo "$KAT_OUT"

kat_expect() { # kat_expect <exact line>
  if printf '%s\n' "$KAT_OUT" | grep -qxF "$1"; then
    echo "KAT OK: $1"; KAT_PASS=$((KAT_PASS+1))
  else
    echo "KAT FAIL: expected exact line: $1" >&2; KAT_FAIL=$((KAT_FAIL+1))
  fi
}

# Fixed inputs → asserted exact computed values (see mayhem/kat/src/main.rs):
kat_expect "KAT1 policy_blocks=4"          # MigPolicy: 4 policy blocks in config/policy.json
kat_expect "KAT2 platform_policies=1"      # one Platform block
kat_expect "KAT3 qe=true migtd=true"       # QE + MigTD blocks present
kat_expect "KAT4 cert_extensions=5"        # X.509: 5 extensions in the SGX Root CA cert
kat_expect "KAT6 reject=true"              # malformed policy + cert REJECTED

emit_ctrf "migtd-kat" "$KAT_PASS" "$KAT_FAIL"
