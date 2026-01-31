# ciph

**ciph** is a fast, streaming file‑encryption tool built for **large media files** and **cloud uploads**. It uses modern, industry‑standard cryptography and is designed to safely encrypt files **larger than your system RAM**.

> Encrypt locally. Upload anywhere. Decrypt only when you trust the environment.

---

## ❓ Why ciph?

Most encryption tools load the entire file into memory before encrypting it. **ciph streams data in fixed-size chunks**, which means you can encrypt a **50 GB 4K video on a machine with only 2 GB of RAM**—smoothly and safely.

## ✨ Features

* 🔐 **Strong encryption** — AES‑256‑GCM or ChaCha20‑Poly1305
* 🔑 **Password protection** — Argon2id (memory‑hard key derivation)
* 🚀 **High performance** — streaming C core (1 MB chunks)
* 🧠 **Constant memory usage** — works with 10 GB+ files
* ⚙️ **Hardware‑aware** — AES‑NI when available, ChaCha fallback
* 🧪 **Integrity protected** — AEAD authentication on every chunk
* ☁️ **Cloud / Telegram safe** — encrypt before upload
* 🏷️ **Filename preserved** — original filename & extension are stored and restored on decryption

---

## 🔐 Cryptographic Design

`ciph` uses a **hybrid (envelope) encryption model**, similar to what is used in modern secure storage systems:

1. A random **data key** encrypts the file in streaming mode.
2. Your password is hardened using **Argon2id**.
3. The data key is encrypted using the derived password key.
4. Every chunk is authenticated to detect tampering.

No custom crypto. No weak primitives.

5. The **original filename (without path)** is stored as encrypted metadata and automatically restored on decryption.

---

## 🔒 Security Strength

| Component                  | Algorithm                                | Strength     |
| -------------------------- | ---------------------------------------- | ------------ |
| File encryption            | AES‑256‑GCM                              | 256‑bit      |
| File encryption (fallback) | ChaCha20‑Poly1305                        | 256‑bit      |
| Password KDF               | Argon2id                                 | Memory‑hard  |
| Integrity                  | AEAD                                     | Tamper‑proof |
| Nonces                     | Key-derived per chunk (unique, no reuse) | No reuse     |

### What this means

* Brute‑force attacks are **computationally infeasible**
* File corruption or tampering is **always detected**
* Encrypted files are safe on **any cloud platform**
* Losing the password means **data is unrecoverable**

---

## 🚀 Quick Start (Build from Source)

```bash
git clone https://github.com/ankit-chaubey/ciph
cd ciph
make
pip install .
```

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

> The original filename and extension are automatically restored, even if the encrypted file was renamed.`

### Example workflow (Cloud / Telegram)

```bash
ciph encrypt movie.mkv
# upload movie.mkv.ciph anywhere
# share the password securely

ciph decrypt movie.mkv.ciph
```

---

## 📝 File Format (V2)

| Offset | Size | Description                            |
| ------ | ---- | -------------------------------------- |
| 0      | 4    | Magic bytes (`CIPH`)                   |
| 4      | 1    | Format version                         |
| 5      | 1    | Cipher mode (1 = AES, 2 = ChaCha)      |
| 6      | 16   | Argon2 salt                            |
| 22     | 12   | Key nonce                              |
| 34     | 1    | Filename length (N)                    |
| 35     | N    | Original filename (UTF‑8)              |
| 35+N   | 2    | Encrypted data‑key length              |
| …      | …    | Encrypted data key + encrypted payload |

## 📊 Performance

* Processes data in **1 MB chunks**
* Cryptography handled in **C (libsodium)**
* Python used only for CLI orchestration
* Typical throughput: **hundreds of MB/s** (CPU‑bound)

Encryption is usually faster than your internet upload speed.

---

## ⚠️ Limitations (v0.1.0)

* Linux / Termux only
* No resume support yet
* Progress bar shows start → finish (stream handled in C)
* Password‑based encryption only (public‑key mode planned)
* Filename metadata is visible (content remains fully encrypted)

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

Copyright © 2026 Ankit Chaubey

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
