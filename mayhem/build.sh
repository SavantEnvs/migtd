#!/usr/bin/env bash
#
# mayhem/build.sh — build migtd's cargo-fuzz parser targets as sanitized libFuzzer
# binaries (OSS-Fuzz Rust path: cargo-fuzz + ASan via RUSTFLAGS) and build the KAT
# oracle probe that mayhem/test.sh RUNS.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The Rust
# toolchain + cargo registry live at $CARGO_HOME=/opt/toolchains/rust/cargo (pinned
# by the Dockerfile ENV — absolute, $HOME-independent).
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
#   - This FIRST build (online) populates the cargo registry under $CARGO_HOME and
#     writes the fuzz/KAT Cargo.lock files into the tree; both persist in the image.
#   - The PATCH re-run resolves crates from that cache (CARGO_NET_OFFLINE=true is
#     exported by the runtime), so we do NOT hard-code `--offline` here.
#
# TOOLCHAIN TRAP: upstream commits a root `rust-toolchain` pinning stable 1.88.0,
# which would hijack every BARE `cargo` in the tree (and stable can't do
# -Zsanitizer=address). So every cargo invocation below uses an explicit
# `+$RUST_CHANNEL` — never bare cargo.
#
# SUBMODULE VENDORING (TDX quirk): the parser targets pull the `crypto`/`policy`/
# `migtd` crates, which depend on PATCHED ring (deps/td-shim/library/ring) and, for
# the migtd-crate targets, spdmlib/codec (deps/spdm-rs). Those are git submodules —
# ABSENT from a clean clone (the gate builds from `git clone . <ctx>`, which does NOT
# fetch submodules). We can't commit regular files at the upstream gitlink paths
# without breaking the all-`A` additive invariant, so the PREPARED+PATCHED submodule
# content (ring patched per sh_script/preparation.sh) is vendored under mayhem/vendor/
# and staged into deps/ HERE, at build time, behind a sentinel (idempotent).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${MAYHEM_JOBS:=$(nproc)}"
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

# The toolchain the Dockerfile installed. Referenced EXPLICITLY (+$RUST_CHANNEL) on
# every cargo invocation so the upstream root `rust-toolchain` (stable 1.88.0) can
# never hijack the channel. Already installed → rustup never hits the network.
RUST_CHANNEL="${RUST_CHANNEL:-nightly-2025-06-01}"
TRIPLE="x86_64-unknown-linux-gnu"

cd "$SRC"

# ── Stage the vendored, PATCHED submodule content into deps/ ───────────────────
# GUARDED by a sentinel so this is IDEMPOTENT (§6.2 item 9):
#   * The offline PATCH re-run starts from the already-built image, where deps/ is
#     already staged and cargo fingerprints/generated files live under the fuzz
#     target dirs. An unconditional re-stage could delete build-time-generated files
#     cargo still believes exist. Skip re-staging → fast offline incremental re-run.
#   * CI (actions/checkout submodules: recursive) populates deps/ with the UNPATCHED
#     submodule content, which has NO sentinel → we DO stage over it with the patched
#     vendor. So the guard is keyed on OUR sentinel, not on mere presence.
if [ ! -f deps/.mayhem-staged ]; then
  echo "=== staging vendored submodule content into deps/ ==="
  for m in td-shim spdm-rs; do
    [ -d "mayhem/vendor/$m" ] || { echo "ERROR: mayhem/vendor/$m missing" >&2; exit 1; }
    rm -rf "deps/$m"
    cp -a "mayhem/vendor/$m" "deps/$m"
  done
  # ring's build.rs generates its perlasm ONLY when it sees a `.git` marker in the
  # crate dir (use_pregenerated = !is_git); otherwise it expects a prebuilt
  # pregenerated/ dir the checkout doesn't ship. We stripped .git while vendoring
  # (git can't track a `.git` entry), so recreate the marker on BOTH patched rings.
  touch "deps/td-shim/library/ring/.git"
  touch "deps/spdm-rs/external/ring/.git"
  touch deps/.mayhem-staged
  echo "staged deps/td-shim, deps/spdm-rs"
else
  echo "=== deps/ already staged (sentinel present) — skipping (idempotent re-run) ==="
fi

# ── Sanitizers (§6.1) ──────────────────────────────────────────────────────────
# The base provides clang $SANITIZER_FLAGS (ASan+UBSan, halting). rustc can't consume
# those clang flags, but we HONOR the knob: non-empty → instrument the Rust build with
# ASan (the OSS-Fuzz Rust path); an explicit empty `--build-arg SANITIZER_FLAGS=`
# yields an un-sanitized build.
RUST_SAN=""
if [ -n "${SANITIZER_FLAGS:-}" ]; then
  RUST_SAN="-Zsanitizer=address"
fi

# ── Debug info (§6.2 item 10): the produced binary MUST carry DWARF < 4 ─────────
# rustc nightly defaults to DWARF-5, so pin -Zdwarf-version=3. The libfuzzer-sys /
# ring cc shims are compiled by clang (DWARF-5 default) → pin their DWARF too.
# $RUST_DEBUG_FLAGS threads any extra base pins.
export RUSTFLAGS="${RUSTFLAGS:-} ${RUST_DEBUG_FLAGS:-} --cfg fuzzing ${RUST_SAN} -Zdwarf-version=3 -Cdebuginfo=1 -Cforce-frame-pointers"
export CFLAGS="${CFLAGS:-} -gdwarf-3"
export CXXFLAGS="${CXXFLAGS:-} -gdwarf-3"

# The bundled ASan runtime archive that `-Zsanitizer=address` links is precompiled
# with clang (DWARF-5) and ships full debug info, which would otherwise land a DWARF-5
# compile unit at .debug_info offset 0 (the FIRST CU) and fail the DWARF < 4 gate.
# Strip debug info from that runtime archive (a toolchain artifact, NOT project code).
# Idempotent — a no-op on an already-stripped archive.
if [ -n "${RUST_SAN}" ]; then
  RT_LIB_DIR="$(rustc +"${RUST_CHANNEL}" --print sysroot)/lib/rustlib/${TRIPLE}/lib"
  for asan in "$RT_LIB_DIR"/librustc-*_rt.asan.a; do
    [ -f "$asan" ] || continue
    if [ -w "$asan" ]; then
      objcopy --strip-debug "$asan" "$asan.stripped" && mv "$asan.stripped" "$asan"
      echo "stripped debug info from bundled ASan runtime: $asan"
    fi
  done
fi

# ── cargo fuzz build ────────────────────────────────────────────────────────────
# Each upstream fuzz crate is its OWN standalone workspace ([workspace] members=["."]),
# so cargo-fuzz writes each binary UNDER that fuzz crate's own target dir
# (<fuzz_dir>/target/<triple>/release/<t>), NOT a root target dir. Only the libFuzzer
# (libfuzzer-sys) parser targets are built — the afl_* bins need cargo-afl + the
# non-default `fuzz` feature and are a separate path.
#
#   FUZZ_DIR                 TARGET               parser
#   src/policy/fuzz          policy               MigPolicy migration-policy JSON (serde_json)
#   src/crypto/fuzz          x509                 X.509 cert DER decode (der / SPDM+TD-report certs)
#   src/migtd/fuzz           service_response     VMCALL SPDM service response framing
#   src/migtd/fuzz           migration_info_hob   TD migration-info HOB (read_mig_info)
declare -a FUZZ_SPECS=(
  "src/policy/fuzz:policy"
  "src/crypto/fuzz:x509"
  "src/migtd/fuzz:service_response"
  "src/migtd/fuzz:migration_info_hob"
)

echo "=== cargo fuzz build (pinned nightly, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"

# AVX-512 nightly trap (netnew §6): rustls-pki-types pulls the newest `zerocopy`
# (0.8.56), which fails on nightly-2025-06-01 with `E0658: stdarch_x86_avx512`. The
# migtd crate already pins `zerocopy = "=0.8.27"` (proven-good on this nightly — the
# `policy` target builds with it), but the crypto/x509 tree has no such constraint and
# grabs 0.8.56. Pin every fuzz crate's lockfile DOWN to 0.8.27 before building. Done on
# the committed-lock-less fuzz crates by generating the lock then downgrading; tolerant
# (`|| true`) for trees where zerocopy is absent or already unified.
pin_zerocopy() {
  local dir="$1"
  cargo +"${RUST_CHANNEL}" generate-lockfile --manifest-path "$dir/Cargo.toml" >/dev/null 2>&1 || true
  cargo +"${RUST_CHANNEL}" update --manifest-path "$dir/Cargo.toml" \
        -p zerocopy --precise 0.8.27 >/dev/null 2>&1 || true
}

for spec in "${FUZZ_SPECS[@]}"; do
  FUZZ_DIR="${spec%%:*}"
  t="${spec##*:}"
  echo "--- building fuzz target: $t (in $FUZZ_DIR) ---"
  pin_zerocopy "$FUZZ_DIR"
  cargo +"${RUST_CHANNEL}" fuzz build --fuzz-dir "$FUZZ_DIR" -O --debug-assertions "$t"
  # standalone (non-root-workspace) fuzz crate → binary lands under ITS OWN target dir.
  bin="$SRC/$FUZZ_DIR/target/$TRIPLE/release/$t"
  [ -x "$bin" ] || { echo "ERROR: expected fuzz binary not found at $bin" >&2; exit 1; }
  cp "$bin" "/mayhem/$t"
  echo "built /mayhem/$t"
done

# ── KAT oracle probe (mayhem/kat — standalone crate, own [workspace]) ───────────
# A small dynamically-linked binary that drives migtd's PUBLIC migration-policy
# (policy::MigPolicy via serde_json) and X.509 (crypto::x509::Certificate) parser
# APIs on FIXED inputs and prints exact known-answer values; mayhem/test.sh greps
# them. Built CLEAN (no sanitizer, normal flags) so it is an honest oracle build.
echo "=== building KAT oracle probe (mayhem/kat, clean flags) ==="
pin_zerocopy mayhem/kat   # same zerocopy/avx512 pin (kat depends on crypto)
env -u RUSTFLAGS -u CFLAGS -u CXXFLAGS \
  cargo +"${RUST_CHANNEL}" build --release --manifest-path mayhem/kat/Cargo.toml
KAT_BIN="$SRC/mayhem/kat/target/release/migtd-kat"
[ -x "$KAT_BIN" ] || { echo "ERROR: KAT probe not built at $KAT_BIN" >&2; exit 1; }
# The anti-reward-hacking oracle only works on a DYNAMICALLY linked binary
# (LD_PRELOAD must reach it) — fail the build if that regresses.
file "$KAT_BIN" | grep -q 'dynamically linked' \
  || { echo "ERROR: KAT probe is not dynamically linked — oracle would be sabotage-immune" >&2; exit 1; }
echo "built KAT probe: $KAT_BIN"

echo "build.sh complete"
