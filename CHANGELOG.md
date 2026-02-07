# Changelog

All notable changes to **CIPH** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/) and follows semantic versioning.

---

## [1.0.0] — Final Stable Release

**Release date:** 2026-02-07

This release marks the first **production‑ready**, **cryptographically stable**, and **performance‑validated** version of CIPH. The engine has been stress‑tested on multi‑gigabyte files, supports adaptive chunking, and guarantees data and filename integrity.

### ✨ Added

* Adaptive chunk decryption (auto‑grows buffers safely)
* Runtime‑configurable chunk size (CLI, environment, API)
* `ciph_set_chunk_mb()` public API
* `ciph_strerror()` for human‑readable error reporting
* Filename preservation and restoration on decrypt
* AES‑256‑GCM and ChaCha20‑Poly1305 support
* Automatic AES → ChaCha fallback on unsupported hardware
* Streaming encryption/decryption for multi‑GB files
* Integration test covering:

  * Cross‑chunk encryption/decryption
  * Cross‑cipher encryption/decryption
  * Integrity verification (SHA‑256)
  * Filename restoration after rename
* GitHub Actions CI pipeline with native build + integration tests

### ⚡ Improved

* Default chunk size increased to **4 MB** (better throughput)
* Constant memory usage regardless of file size
* Faster encryption/decryption on large files
* Robust error propagation from C → Python CLI
* Cleaner, deterministic CLI UX with progress bars

### 🔒 Security

* Strict bounds checking on encrypted chunk sizes
* Memory zeroing for sensitive buffers
* Protection against malicious chunk inflation attacks
* Password verification hardened against corruption cases

### 🛠️ Changed

* CLI defaults to AES (with automatic fallback)
* Chunk size no longer required to match between encrypt/decrypt
* Build system standardized via Makefile + setuptools

### 🧹 Removed

* Fixed‑size chunk assumptions
* Silent failures and ambiguous error messages
* Hard dependency on matching encryption parameters

---

## [0.1.1] — Pre‑Stable Beta

### Added

* Initial streaming encryption engine
* Python CLI wrapper
* Basic AES and ChaCha support

### Known Limitations (resolved in 1.0.0)

* Fixed chunk size
* Weak error reporting
* No adaptive decryption
* Limited test coverage

---

## Upgrade Notes

Upgrading from **0.1.1 → 1.0.0** is fully backward‑compatible.

Encrypted files created with earlier versions **decrypt correctly** in 1.0.0.

No action required.

---

**CIPH 1.0.0 is production‑ready.**
