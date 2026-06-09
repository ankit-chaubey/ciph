# Changelog

## [1.2.2] - 2026-06-09

- Code and docs cleanup

## [1.2.1] - 2026-02-08

Protocol hardening release. No CLI changes.

### Added
- Full header authentication (AAD binding) -- all metadata cryptographically tied to ciphertext
- Key separation: enc key and nonce key derived independently with domain separation
- Per-chunk nonces derived from secret key + chunk index (replay/reorder protection)
- Explicit password handling (raw bytes, explicit length)
- DoS-safe streaming: encrypted chunk sizes validated before allocation

### Security
- Metadata tampering (magic, version, cipher, chunk size, filename, salt) now always detected
- Cipher downgrade attacks not possible
- Chunk replay, reordering, duplication, cross-file transplantation not possible
- Nonce reuse under the same key not possible

### Changed
- Python CLI bindings updated to match hardened native API
- Password handling no longer relies on C-string assumptions

### Compatibility
- Existing encrypted files decrypt correctly
- No CLI or API changes

## [1.2.0] - 2026-02-07

First production-ready release.

### Added
- Adaptive chunk decryption
- Runtime-configurable chunk size (CLI, env, API)
- `ciph_set_chunk_mb()` and `ciph_strerror()` public API
- Filename preservation and restoration on decrypt
- AES-256-GCM and ChaCha20-Poly1305 support
- Automatic AES -> ChaCha fallback on unsupported hardware
- Integration tests (cross-chunk, cross-cipher, integrity, filename restore)
- GitHub Actions CI

### Changed
- Default chunk size increased to 4 MB
- Chunk size no longer required to match between encrypt and decrypt
- Build via Makefile and setuptools

## [1.1.0] - 2026-01 (approx.)

Initial beta. Basic streaming encryption, Python CLI, AES + ChaCha support.
Known issues: fixed chunk size, weak error reporting, partial header auth. All resolved in 1.2.0.
