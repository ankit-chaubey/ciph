# Security Policy

## 🔐 Security Overview

**ciph** is a security-focused project that uses modern, well-reviewed cryptographic primitives (via **libsodium**) and a streaming design to safely encrypt large files.

Security is a first-class concern for this project. If you discover a vulnerability or have concerns about the cryptographic design, please follow the responsible disclosure process below.

---

## 🧪 Supported Versions

The following versions currently receive security attention:

| Version | Supported |
| ------- | --------- |
| 0.2.x   | ✅ Yes     |
| 0.1.x   | ✅ Yes     |
| < 0.1   | ❌ No      |

---

## 🛡️ Cryptographic Design Principles

ciph follows these core security principles:

* Uses **standard, audited cryptography** (AES-256-GCM, ChaCha20-Poly1305, Argon2id)
* Avoids custom cryptographic algorithms
* Uses **streaming encryption** to prevent memory exhaustion
* Applies **authenticated encryption (AEAD)** to detect tampering
* Derives per-chunk nonces using a **key-derived, no-reuse scheme**
* Clears sensitive key material from memory after use

The design follows the same high-level envelope encryption pattern used in modern secure storage systems.

---

## 📁 Metadata Considerations

To improve usability, **ciph stores the original filename (without path)** inside the encrypted file header.

* The filename is **not encrypted metadata** and may be visible to someone inspecting the file structure.
* File *contents* remain fully encrypted and authenticated.

If metadata privacy is critical for your use case, consider renaming files before encryption or using an additional wrapper.

---

## 🚨 Reporting a Vulnerability

If you believe you have found a security vulnerability:

* **Do not open a public GitHub issue.**
* Please report the issue privately.

### Contact

* Email: **m DOT ankitchaubey AT gmail DOT com**
* Subject line: `SECURITY: ciph vulnerability report`

Please include:

* A clear description of the issue
* Steps to reproduce (if applicable)
* Potential impact
* Any suggested fixes or references

You will receive an acknowledgment within **72 hours**.

---

## ⏱️ Disclosure Timeline

* The maintainer will investigate all reports promptly.
* If a vulnerability is confirmed, a fix will be developed and released.
* Coordinated disclosure will be handled responsibly to protect users.

---

## ⚠️ Scope Limitations

The following are **out of scope** for vulnerability reports:

* Lost or forgotten passwords
* Weak user-chosen passwords
* Compromised systems or malware
* Attacks requiring physical access
* Social engineering

---

## 📜 Disclaimer

This project is provided **"as is"**, without warranty of any kind.

Cryptography is a complex field. While best practices are followed, no security software can guarantee absolute protection.

Use responsibly.
