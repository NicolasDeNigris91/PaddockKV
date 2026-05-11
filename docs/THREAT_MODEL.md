# Threat model — Encryption at rest

This document describes exactly what the encryption-at-rest feature
protects against and, equally importantly, what it does **not** protect
against. Honesty about the boundary is the point — silent over-promising
is worse than no encryption at all.

> Status: cryptographic primitives delivered and validated against a
> published AES-256-GCM test vector. SSTable writer / reader integration
> lands in Phase 8b. The threat model below describes the design once
> integration ships; the present code already enforces every property at
> the primitive layer.

## In scope

The engine is designed to protect data confidentiality and integrity
**against an attacker with read access to the database files but no
ability to execute code as the engine process**. Concrete scenarios:

- **Stolen disk / decommissioned hardware.** A drive pulled from a
  retired server, a misplaced laptop, a backup tape recovered from a
  dumpster. The attacker has the raw bytes; they do not have the master
  key.
- **Misconfigured filesystem permissions.** A separate user account or
  container on the same host can `read()` the SSTable files but cannot
  attach a debugger to the engine or read its memory.
- **Unprivileged backup process.** A backup agent that reads the data
  directory has no way to recover plaintext values from the snapshot.
- **Block-level cut-and-paste.** An attacker who can write the data
  directory (but cannot read the master key) cannot lift a ciphertext
  block from SSTable A into SSTable B: per-SSTable keys mean the
  authentication tag computed under A's key fails to verify under B's,
  and the AEAD `open` rejects the block.

## Out of scope

The engine **does not** protect against:

- **Memory disclosure.** A debugger, core dump, swap file, or
  /proc/$PID/mem read exposes the master key (held in `MasterKey`),
  every derived per-SSTable key currently in use, and any plaintext
  values transiting through the page cache via mmap. If you mmap-read
  encrypted SSTables, decrypted plaintext lives in your address space.
  An attacker with this capability owns the data.
- **Code execution as the engine UID.** Anyone who can run code as the
  engine's user can construct a `Db` handle, call `db.get(key)`, and
  read plaintext. Encryption is irrelevant in this scenario.
- **Side-channel attacks on the cipher.** AES-NI on contemporary x86_64
  parts is largely (but not entirely) constant-time. On hosts without
  AES-NI, the `aes` crate falls back to a constant-time bitslice
  software implementation. The engine does no extra hardening (e.g.
  cache-flushing between blocks, prefetch perturbation) so a co-resident
  attacker with precise timing measurements may extract bits.
  Hardening the side-channel posture is future work; today, run the
  engine on dedicated hardware or carefully sandboxed VMs.
- **Forward secrecy.** Rotating the master key today requires
  re-encrypting every SSTable. The engine has no online rotation
  pathway; a planned Phase 8c will stage rotation by emitting new
  SSTables under a fresh master while keeping the old one available for
  reads.
- **Denial of service via tampering.** Although the AEAD layer
  *detects* every modification of the ciphertext, an attacker who can
  flip a single bit anywhere in the SSTable will cause that block's
  read to fail. The engine reports the failure as
  [`crate::error::Error::Corruption`](../crates/paddock-core/src/error.rs);
  it does not silently fall back to a usable subset.
- **Metadata leakage.** The engine encrypts data-block payloads. It
  does **not** encrypt:
  - The SSTable filename or its file size (visible to anyone with
    directory read access).
  - The Bloom filter bytes (Phase 5). Bloom filters reveal a small
    amount of information about which keys *might* be present — they
    are designed to enable that lookup. If your threat model includes
    "the attacker must not learn whether a given key is plausibly in
    the database," disable the Bloom filter (`expected_keys = 0` in
    `SstWriter::create_with_filter_capacity`).
  - The number of records or the range of sequence numbers (in the
    SSTable file header).
  - The keys themselves at insertion / lookup time when transmitted to
    the engine. The engine is a library; the calling process owns the
    transport.

## Cryptographic primitives

| Primitive             | Construction                                  |
|-----------------------|-----------------------------------------------|
| AEAD                  | AES-256-GCM (RFC 5288 / NIST SP 800-38D)      |
| Key derivation        | HKDF-SHA256 (RFC 5869)                        |
| Master key length     | 256 bits                                      |
| Per-SSTable key length| 256 bits, derived from master + sstable id    |
| Nonce length          | 96 bits (spec-recommended)                    |
| Authentication tag    | 128 bits                                      |

### Nonce reuse

AES-GCM is catastrophically broken under nonce reuse. The engine prevents
reuse structurally:

1. Every SSTable has its own AES-256-GCM key, derived via
   `HKDF(master, info = "paddockkv:sstable:v1:" || sstable_id_le)`.
2. Within a single SSTable, every block carries a deterministic nonce
   computed from the block index: `nonce = "NONC" || block_index_le`.
3. Block indices within an SSTable are monotonic and never reused — the
   SSTable is immutable once flushed.

It follows that no `(key, nonce)` pair can ever repeat within a single
engine instance, even across crashes and restarts. This is the most
important security invariant the implementation establishes; the test
suite in `crypto::envelope::tests` exercises both the per-block and
per-SSTable defenses against cut-and-paste attacks.

### Associated data

Each encrypted block carries 16 bytes of AAD authenticated by GCM:
`(sstable_id_le, block_index_le)`. Tampering with either coordinate
breaks the tag verification at `open` time. This is what defeats the
inter-SSTable cut-and-paste attack: even if the same plaintext is
encrypted twice (different SSTables, different keys, different AAD),
neither ciphertext can replace the other.

### Key storage

The engine receives the master key from the operator. It does not
generate or store the key on its own; persistence of the master key is
the operator's responsibility (KMS, HSM, sealed envelope, etc.). The
engine logs `MasterKey` and `AeadKey` debug output with the key bytes
elided — operational logs never expose the secret.

## Auditing scope

A third-party reviewer should be able to assess the engine's security
posture by reading:

- `crates/paddock-core/src/crypto/aead.rs` — AEAD wrapper, AES-256-GCM
- `crates/paddock-core/src/crypto/kdf.rs` — HKDF-SHA256 key hierarchy
- `crates/paddock-core/src/crypto/envelope.rs` — nonce + AAD
  construction
- `docs/THREAT_MODEL.md` — this document
- `docs/format/sstable.md` — on-disk layout (covers the encrypted-block
  framing once Phase 8b lands)

External dependencies that touch ciphertext or keys:

- `aes-gcm = 0.10` — the RustCrypto AEAD wrapper. Audited public crate;
  delegates the block cipher to the `aes` crate.
- `aes`     — RustCrypto block cipher; AES-NI dispatch on x86_64, ARM
  Crypto extension on ARM64, constant-time bitslice fallback.
- `hkdf`    — RustCrypto HKDF.
- `sha2`    — RustCrypto SHA-256.

## Reporting

Suspected vulnerabilities should be reported privately via the contact
address listed in `Cargo.toml`'s `authors` field; do not open a public
issue.
