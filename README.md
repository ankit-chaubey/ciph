# ciph

[![PyPI](https://img.shields.io/pypi/v/ciph.svg)](https://pypi.org/project/ciph/)
[![Downloads](https://img.shields.io/pypi/dm/ciph.svg)](https://pypi.org/project/ciph/)
[![Python](https://img.shields.io/pypi/pyversions/ciph.svg)](https://pypi.org/project/ciph/)
[![CI](https://github.com/ankit-chaubey/ciph/actions/workflows/ciph-test.yml/badge.svg)](https://github.com/ankit-chaubey/ciph/actions/workflows/ciph-test.yml)
[![License](https://img.shields.io/github/license/ankit-chaubey/ciph)](https://github.com/ankit-chaubey/ciph/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/tag/ankit-chaubey/ciph?label=release)](https://github.com/ankit-chaubey/ciph/releases)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Termux-blue)](#)
[![Crypto](https://img.shields.io/badge/crypto-AES--256--GCM%20%7C%20ChaCha20--Poly1305-blue)](#)

**ciph** is a fast, streaming file‑encryption tool built for **large media files** and **cloud uploads**. It uses modern, industry‑standard cryptography and is designed to safely encrypt files **larger than your system RAM**.

> Encrypt locally. Upload anywhere. Decrypt only when you trust the environment.

---

## ❓ Why ciph?

Most encryption tools load the entire file into memory before encrypting it. **ciph streams data in fixed-size chunks**, which means you can encrypt a **50 GB 4K video on a machine with only 2 GB of RAM**—smoothly and safely.

Unlike archive-based or buffer-based tools, ciph never needs random access to plaintext and never allocates memory proportional to file size. Memory usage is deterministic and bounded.

---

## ✨ Features

* 🔐 **Strong encryption** — AES‑256‑GCM or ChaCha20‑Poly1305
* 🔑 **Password protection** — Argon2id (memory‑hard key derivation)
* 🚀 **High performance** — streaming C core with configurable chunk size
* 🧠 **Constant memory usage** — works with 10 GB+ files
* ⚙️ **Hardware‑aware** — AES‑NI when available, ChaCha fallback
* 🧪 **Integrity protected** — AEAD authentication on every chunk
* ☁️ **Cloud / Telegram safe** — encrypt before upload
* 🏷️ **Filename preserved** — original filename & extension are stored and restored on decryption
* 🧷 **Rename‑safe** — encrypted files may be freely renamed
* 🧯 **Fail‑closed design** — corruption always aborts decryption

---

## 🔐 Cryptographic Design

`ciph` uses a **hybrid (envelope) encryption model**, similar to what is used in modern secure storage systems:

1. A random **data key** encrypts the file in streaming mode.
2. Your password is hardened using **Argon2id**.
3. The data key is encrypted using the derived password key.
4. Every chunk is authenticated to detect tampering.
5. The **original filename (without path)** is stored as authenticated metadata and automatically restored on decryption.

No custom crypto. No weak primitives. No silent failure modes.

---

## 🔒 Security Strength

| Component                  | Algorithm                                | Strength     |
| -------------------------- | ---------------------------------------- | ------------ |
| File encryption            | AES‑256‑GCM                              | 256‑bit      |
| File encryption (fallback) | ChaCha20‑Poly1305                        | 256‑bit      |
| Password KDF               | Argon2id                                 | Memory‑hard  |
| Integrity                  | AEAD                                     | Tamper‑proof |
| Nonces                     | Key‑derived per chunk (unique, no reuse) | No reuse     |

### What this means

* Brute‑force attacks are **computationally infeasible**
* File corruption or tampering is **always detected**
* Encrypted files are safe on **any cloud platform**
* Losing the password means **data is unrecoverable**

---

## 🆕 Security Update (v1.2.0 — Hardened)

Starting from **v1.2.0**, ciph introduces a **protocol‑level security hardening**. This update does **not** change the user workflow, but it significantly strengthens the internal guarantees.

### What changed internally

* 🔒 **Full metadata authentication (AAD binding)**  
  All file header fields (magic, version, cipher, chunk size, salt, nonce key, filename, encrypted key) are cryptographically bound to the encrypted content. Any modification causes decryption to fail.

* 🔑 **Strict key separation**  
  Encryption keys and nonce‑derivation keys are derived independently using domain separation. Keys are never reused across purposes.

* 🔁 **Chunk replay & reordering protection**  
  Each encrypted chunk uses a nonce derived from a secret key and the chunk index. Chunks cannot be reordered, duplicated, or transplanted between files.

* 🧼 **Explicit password handling**  
  Passwords are treated as raw byte buffers with explicit length. No implicit string handling, truncation, or hidden transformations.

* 🛡️ **DoS‑safe streaming**  
  Encrypted chunk sizes are validated before allocation to prevent memory exhaustion attacks.

### What is now cryptographically impossible

* ❌ Modifying the filename without detection
* ❌ Downgrading the cipher mode
* ❌ Swapping or reordering encrypted chunks
* ❌ Transplanting chunks between different files
* ❌ Reusing nonces under the same key
* ❌ Injecting malformed headers that decrypt silently

---

## 🚀 Quick Start (Build from Source)

```bash
git clone https://github.com/ankit-chaubey/ciph
cd ciph
make
pip install .
```

---

## 📦 Installation

### Requirements

* Linux / Termux
* Python ≥ 3.8
* libsodium

### Install from PyPI

```bash
pip install ciph
```

---

## 🚀 Usage

### Encrypt a file

```bash
ciph encrypt video.mp4
```

Output:

```
video.mp4.ciph
```

### Decrypt a file

```bash
ciph decrypt video.mp4.ciph
```

Output:

```
video.mp4
```

> The original filename and extension are automatically restored, even if the encrypted file was renamed.

### Example workflow (Cloud / Telegram)

```bash
ciph encrypt movie.mkv
# upload movie.mkv.ciph anywhere
# share the password securely

ciph decrypt movie.mkv.ciph
```

---

## 📝 File Format

> **Extended without removing any fields**. All original fields remain present; guarantees are clarified and enforced.

### Header Layout (Authenticated as AAD)

| Offset | Size | Description                                            |
| ------ | ---- | ------------------------------------------------------ |
| 0      | 4    | Magic bytes (`CIPH`)                                   |
| 4      | 1    | Format version                                         |
| 5      | 1    | Cipher mode (1 = AES‑256‑GCM, 2 = ChaCha20‑Poly1305)   |
| 6      | 4    | Chunk size in MB (big‑endian)                          |
| 10     | 16   | Argon2id salt (random per file)                        |
| 26     | 12   | Nonce‑derivation key (random per file)                 |
| 38     | 1    | Filename length (N)                                    |
| 39     | N    | Original filename (UTF‑8, no path, not NUL‑terminated) |
| 39+N   | 2    | Encrypted data‑key length (big‑endian)                 |
| 41+N   | L    | Encrypted data key (AEAD‑protected)                    |

> **All header fields above are cryptographically authenticated (AAD)**. Any modification results in decryption failure.

### Encrypted Payload Layout (Streaming)

| Field     | Size | Description                                  |
| --------- | ---- | -------------------------------------------- |
| ChunkLen  | 4    | Length of encrypted chunk (ciphertext + tag) |
| ChunkData | M    | AEAD‑encrypted chunk data                    |

This pair repeats until end‑of‑file. A final authenticated zero‑length chunk acts as an EOF marker.

### Cryptographic Binding Guarantees (v1.2.0+)

The following properties are **cryptographically enforced**, not policy‑based:

* Header ↔ payload binding (no metadata tampering)
* Cipher mode binding (no downgrade attacks)
* Filename binding (cannot be altered silently)
* Chunk order binding (no reordering or replay)
* Cross‑file isolation (chunks cannot be transplanted)

---

## 📊 Performance

* Processes data in **(1–1024) MB chunks**
* Cryptography handled in **C (libsodium)**
* Python used only for CLI orchestration
* Typical throughput: **hundreds of MB/s** (CPU‑bound)

Encryption is usually faster than your internet upload speed.

---

## ⚠️ Limitations (v1.0.0+)

* No resume support yet
* Progress bar shows start → finish (stream handled in C)
* Password‑based encryption only (public‑key mode planned)

---

## 🧑‍💻 Author & Project

**ciph** is **designed, developed, and maintained** by

[**Ankit Chaubey (@ankit‑chaubey)**](https://github.com/ankit-chaubey)

GitHub Repository:
👉 **[https://github.com/ankit-chaubey/ciph](https://github.com/ankit-chaubey/ciph)**

The project focuses on building **secure, efficient, and practical cryptographic tools** for real‑world usage, especially for media files and cloud storage.

---

## 📜 License

Apache License 2.0

Copyright © 2026–present Ankit Chaubey

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

[https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

---

## 🔮 Roadmap

Planned future improvements:

* Parallel chunk encryption
* Resume / partial decryption
* Public‑key encryption mode
* Real‑time progress callbacks
* Prebuilt wheels (manylinux)

---

## ⚠️ Disclaimer

This tool uses strong cryptography.

If you forget your password, **your data cannot be recovered**.

Use responsibly.
