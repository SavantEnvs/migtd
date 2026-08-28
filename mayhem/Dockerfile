# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile — migtd (Rust / cargo-fuzz, Intel TDX Migration firmware).
# Builds ON TOP of the org C/C++ base (ghcr.io/savantenvs/base), adding a pinned
# Rust nightly + cargo-fuzz under /opt/toolchains/rust, then runs mayhem/build.sh.
#
# WHY a pinned nightly at a fixed prefix (SPEC §6.2 items 8/9, §6.5): the Rust
# toolchain and its cargo registry are NOT in the base. We install them at a
# FIXED, $HOME-independent prefix (/opt/toolchains/rust) with CARGO_HOME/RUSTUP_HOME
# pinned there so the registry the FIRST (online) build populates is found again by
# the air-gapped PATCH re-run (which has NO network + a different $HOME).
#
# TDX quirk: upstream pins stable `1.88.0` (root rust-toolchain), but its cargo-fuzz
# targets + the vendored td-shim/spdm-rs/ring compile cleanly on the fleet-proven
# nightly-2025-06-01, which is what -Zsanitizer=address needs (stable can't do it).
# We reference the channel EXPLICITLY (+$RUST_CHANNEL) on every cargo call in
# build.sh/test.sh so the upstream root rust-toolchain file can't hijack it.
#
# Build (from the repo root, on the `mayhem` branch):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) -t migtd-commit:test .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (never an ENV — an empty ENV breaks clang). build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH
# Undefaulted (no '=') so the base ENV default flows through unless --build-arg overrides it.
ARG SANITIZER_FLAGS

# ── Rust toolchain @ a FIXED, lockable, $HOME-independent prefix ───────────────
ARG RUST_CHANNEL=nightly-2025-06-01
ARG CARGO_FUZZ_VERSION=0.12.0

ENV RUSTUP_HOME=/opt/toolchains/rust/rustup \
    CARGO_HOME=/opt/toolchains/rust/cargo \
    PATH=/opt/toolchains/rust/cargo/bin:${PATH} \
    RUST_CHANNEL=nightly-2025-06-01

USER root
# nasm: td-shim's build.rs assembles ResetVector.nasm with `nasm` (upstream CI uses
# ilammy/setup-nasm). It is NOT in the C/C++ base, so install it here — a baked layer,
# so the air-gapped PATCH re-run needs no network for it.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nasm \
 && rm -rf /var/lib/apt/lists/*

RUN install -d /opt/toolchains/rust \
 && curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o /tmp/rustup-init.sh \
 && sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal \
        --default-toolchain "${RUST_CHANNEL}" \
 && rustup component add rust-src --toolchain "${RUST_CHANNEL}" \
 && cargo install cargo-fuzz --version "${CARGO_FUZZ_VERSION}" --locked \
 && rm -f /tmp/rustup-init.sh \
 # The commit build AND the air-gapped PATCH re-run run as `mayhem` (2000): it must
 # read the toolchain and read/refresh the cargo registry cache, so hand the whole
 # prefix to 2000.
 && chown -R 2000:2000 /opt/toolchains/rust

# Source enters from the build CONTEXT (CI checkout): the FULL repo (incl. .git) → /mayhem.
USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Populates $CARGO_HOME (online, this first build) and builds the sanitized fuzz target(s).
RUN bash mayhem/build.sh

# Run the functional oracle at build time (a failing suite fails the build).
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
