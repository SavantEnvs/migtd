// KAT (known-answer test) oracle probe for the migtd Mayhem integration.
//
// Drives migtd's PUBLIC parser APIs on FIXED inputs and prints exact, deterministic
// values. mayhem/test.sh runs this binary and greps the exact expected lines
// (SPEC §6.3 anti-reward-hacking): a PATCH that neuters the policy/crypto crates (or
// this probe) changes/eliminates the output and the oracle FAILS. No file I/O, no
// network — the inputs are baked in via include_bytes!.
//
// These are the SAME code paths the fuzz targets exercise:
//   * src/policy/fuzz `policy` target:  serde_json::from_slice::<policy::MigPolicy>
//   * src/crypto/fuzz `x509`  target:   crypto::x509::Certificate::from_der

use crypto::x509::{Certificate, Decode};
use policy::MigPolicy;

// The migration-policy JSON shipped at config/policy.json (the `policy` fuzz format).
static POLICY_JSON: &[u8] = include_bytes!("../policy.json");
// A real DER X.509 certificate (Intel SGX Provisioning Certification Root CA) — the
// `x509` fuzz format.
static ROOT_CA_DER: &[u8] = include_bytes!("../root_ca.der");

fn main() {
    // ── KAT1..3: migration-policy parser (policy::MigPolicy) ────────────────────
    let policy: MigPolicy = serde_json::from_slice(POLICY_JSON).expect("KAT parse MigPolicy");
    println!("KAT1 policy_blocks={}", policy.blocks.len()); // 4
    println!(
        "KAT2 platform_policies={}",
        policy.get_platform_info_policy().len()
    ); // 1
    println!(
        "KAT3 qe={} migtd={}",
        policy.get_qe_info_policy().is_some(),
        policy.get_migtd_info_policy().is_some()
    ); // true true

    // ── KAT4..5: X.509 DER parser (crypto::x509::Certificate) ───────────────────
    let cert = Certificate::from_der(ROOT_CA_DER).expect("KAT parse Certificate");
    let num_ext = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .expect("KAT extensions present")
        .get()
        .len();
    println!("KAT4 cert_extensions={num_ext}"); // 5

    // ── KAT6: reject paths — a neutered parser that "accepts everything" also fails.
    let reject_policy = serde_json::from_slice::<MigPolicy>(&[0u8, 1, 2, 3]).is_err();
    let reject_cert = Certificate::from_der(&[0x30u8, 0x82]).is_err();
    println!("KAT6 reject={}", reject_policy && reject_cert); // true
}
