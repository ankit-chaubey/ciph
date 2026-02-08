# Changelog

All notable changes to **CIPH** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/) and follows semantic versioning.

---

## [1.2.1] — Protocol Hardening & Security Finalization

**Release date:** 2026-02-08

This release introduces **protocol-level cryptographic hardening**. No user-facing workflow or CLI behavior has changed, but the internal security guarantees have been **formally strengthened and locked in**.

This version elevates CIPH from *strong encryption* to a **vault-grade, protocol-hardened encryption format**.

### ✨ Added

* Full **header authentication (AAD binding)** — all metadata is cryptographically bound to encrypted content
* Strict **key separation (domain separation)** between encryption keys and nonce-derivation keys
* Deterministic, secret-derived **per-chunk nonces**
* Explicit password API (raw bytes + explicit length)
* Formal **file format v2+ (hardened)** documentation
* SECURITY.md describing threat model, invariants, and guarantees
* Enforced cryptographic invariants by construction (not convention)
* Header ↔ payload binding guarantees documented and locked
* Deterministic EOF authentication semantics

### 🔒 Security

* Prevents metadata tampering (magic, version, cipher, chunk size, filename, salt)
* Prevents cipher downgrade attacks
* Prevents chunk replay, reordering, duplication, and cross-file transplantation
* Prevents nonce reuse under the same key
* Stronger resistance to malformed or malicious encrypted inputs (DoS hardening)
* Explicit failure on truncation, corruption, or header manipulation
* No master keys, recovery paths, or hidden decrypt logic

### 🛠️ Changed

* File format header is now **fully authenticated** using AEAD AAD
* Python CLI bindings updated to match hardened native API semantics
* Password handling no longer relies on C-string assumptions
* Cryptographic guarantees are enforced structurally, not by policy or convention
* Documentation aligned exactly with the shipped C implementation

### ⚠️ Compatibility

* User workflow and CLI usage remain unchanged
* Existing encrypted files continue to decrypt correctly
* Re-encryption is **not required**, but recommended for maximum guarantees
* No breaking API or ABI changes

---

## [1.2.1] — Final Stable Release

**Release date:** 2026-02-07

This release marks the first **production-ready**, **cryptographically stable**, and **performance-validated** version of CIPH. The engine has been stress-tested on multi-gigabyte files, supports adaptive chunking, and guarantees data and filename integrity.

### ✨ Added

* Adaptive chunk decryption (auto-grows buffers safely)
* Runtime-configurable chunk size (CLI, environment, API)
* `ciph_set_chunk_mb()` public API
* `ciph_strerror()` for human-readable error reporting
* Filename preservation and restoration on decrypt
* AES-256-GCM and ChaCha20-Poly1305 support
* Automatic AES → ChaCha fallback on unsupported hardware
* Streaming encryption/decryption for multi-GB files
* Integration tests covering:

  * Cross-chunk encryption/decryption
  * Cross-cipher encryption/decryption
  * Integrity verification (SHA-256)
  * Filename restoration after rename
* GitHub Actions CI pipeline with native build and integration tests

### ⚡ Improved

* Default chunk size increased to **4 MB** for better throughput
* Constant memory usage regardless of file size
* Faster encryption/decryption on large files
* Robust error propagation from C core to Python CLI
* Cleaner, deterministic CLI UX with progress indicators

### 🔒 Security

* Strict bounds checking on encrypted chunk sizes
* Memory zeroing for sensitive buffers
* Protection against malicious chunk inflation attacks
* Password verification hardened against corruption cases

### 🛠️ Changed

* CLI defaults to AES with automatic ChaCha fallback
* Chunk size no longer required to match between encrypt and decrypt
* Build system standardized via Makefile and setuptools

### 🧹 Removed

* Fixed-size chunk assumptions
* Silent failures and ambiguous error messages
* Hard dependency on matching encryption parameters

---

## [1.1.0] — Pre-Stable Beta

**Release date:** 2026-01 (approx.)

### ✨ Added

* Initial streaming encryption engine
* Python CLI wrapper
* Basic AES and ChaCha support
* Early file-format layout

### ⚠️ Known Limitations (resolved in 1.2.1)

* Fixed chunk size
* Weak error reporting
* No adaptive decryption
* Limited test coverage
* Partial header authentication

---

## Upgrade Notes

Upgrading from **1.2.0 → 1.2.1** is fully backward-compatible.

Encrypted files created with earlier versions **decrypt correctly** in 1.2.1.

No action required.

For maximum long-term guarantees, re-encryption with ≥1.2.1 is recommended but not mandatory.

---

**CIPH 1.2.1 is protocol-hardened, audit-ready, and designed for hostile storage environments.**
