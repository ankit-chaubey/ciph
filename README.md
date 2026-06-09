# ciph

[![PyPI](https://img.shields.io/pypi/v/ciph.svg)](https://pypi.org/project/ciph/)
[![Downloads](https://img.shields.io/pypi/dm/ciph.svg)](https://pypi.org/project/ciph/)
[![Python](https://img.shields.io/pypi/pyversions/ciph.svg)](https://pypi.org/project/ciph/)
[![CI](https://github.com/ankit-chaubey/ciph/actions/workflows/ciph-test.yml/badge.svg)](https://github.com/ankit-chaubey/ciph/actions/workflows/ciph-test.yml)
[![License](https://img.shields.io/github/license/ankit-chaubey/ciph)](https://github.com/ankit-chaubey/ciph/blob/main/LICENSE)

Fast, streaming file encryption for large files. Works on files bigger than your RAM.

## Install

```bash
pip install ciph
ciph setup
```

**Requirements:** Linux/Termux, Python >= 3.8, libsodium

```bash
# Debian/Ubuntu
sudo apt install libsodium-dev

# Termux
pkg install libsodium
```

Or build from source:

```bash
git clone https://github.com/ankit-chaubey/ciph
cd ciph && make && pip install .
```

## Usage

```bash
ciph encrypt video.mp4          # -> video.mp4.ciph
ciph decrypt video.mp4.ciph     # -> video.mp4 (filename restored)
```

Set cipher or chunk size:

```bash
ciph encrypt file.bin --cipher chacha -c 8
```

Non-interactive (scripting):

```bash
CIPH_PASSWORD=yourpassword ciph encrypt file.bin
```

## How it works

- AES-256-GCM or ChaCha20-Poly1305 (auto-fallback if no AES-NI)
- Argon2id key derivation from password
- Data key is randomly generated per file, then wrapped with the password key
- File is encrypted in chunks (default 4 MB) so memory usage is constant
- Each chunk gets a unique derived nonce, authenticated with the full header as AAD
- Original filename stored in header, restored on decrypt
- Chunk size used during encrypt is baked into the header -- you can decrypt with any `-c` value

## File format

| Offset | Size | Field |
|--------|------|-------|
| 0      | 4    | Magic (`CIPH`) |
| 4      | 1    | Version |
| 5      | 1    | Cipher (1=AES, 2=ChaCha) |
| 6      | 4    | Chunk size MB (big-endian) |
| 10     | 16   | Argon2id salt |
| 26     | 12   | Nonce-derivation key |
| 38     | 1    | Filename length |
| 39     | N    | Original filename |
| 39+N   | 2    | Encrypted key length |
| 41+N   | L    | Encrypted data key |

Followed by repeating `[4-byte chunk length][encrypted chunk]`. A final zero-length authenticated chunk marks EOF.

The entire header is bound as AAD to every chunk -- tampering with any field breaks decryption.

## Limitations

- No resume support
- Password-based only (public-key mode not yet implemented)

## License

Apache 2.0 -- see [LICENSE](LICENSE)
