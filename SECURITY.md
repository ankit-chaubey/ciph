# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.2.x   | Yes       |
| < 1.2   | No        |

## Design

- AES-256-GCM or ChaCha20-Poly1305 via libsodium
- Argon2id for password KDF
- AEAD authentication on every chunk
- Per-chunk nonces derived from a secret key + index (no reuse)
- Full header authenticated as AAD -- any tampering breaks decryption
- Sensitive key material zeroed from memory after use

## Metadata note

The original filename (without path) is stored in the encrypted file header. It's authenticated but not encrypted, so someone inspecting the file structure can see it. File contents are fully encrypted. If that matters for your use case, rename the file before encrypting.

## Reporting a vulnerability

Don't open a public issue.

Email: m.ankitchaubey@gmail.com  
Subject: `SECURITY: ciph vulnerability report`

Include: description, steps to reproduce, potential impact.  
Response within 72 hours.

## Out of scope

- Forgotten passwords (data is unrecoverable by design)
- Weak user-chosen passwords
- Compromised host systems
- Physical access attacks
