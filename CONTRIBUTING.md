# Contributing to ciph

Thank you for your interest in contributing to **ciph** 🙌

ciph is a security‑focused project. Contributions are welcome, but **correctness, clarity, and safety** matter more than speed or feature count.

---

## 🧭 Guiding Principles

When contributing, please keep these principles in mind:

* 🔐 **Security first** — cryptographic safety is non‑negotiable
* 📖 **Transparency** — clear code and clear documentation
* 🧪 **Test before merge** — changes must be verifiable
* 🧠 **Simplicity** — avoid unnecessary complexity

If a change weakens security, it will not be accepted, even if it improves performance.

---

## 📦 Project Structure

```
ciph/
├── ciph.c           # Core cryptographic logic (C / libsodium)
├── ciph.h           # Public C interface
├── ciph/            # Python package
│   ├── cli.py       # CLI wrapper
│   └── _native/     # Compiled shared library (.so)
├── test_ciph.sh     # Integration test
├── README.md
├── SECURITY.md
└── pyproject.toml
```

Please keep cryptographic logic in **C**, not Python.

---

## 🛠️ Development Setup

### Requirements

* Linux / Unix (or Termux)
* Python ≥ 3.8
* `libsodium` development headers
* `gcc` / `clang`

### Build from source

```bash
git clone https://github.com/ankit-chaubey/ciph
cd ciph
make
pip install -e .
```

---

## 🧪 Testing

Before submitting a pull request, you **must** run the integration test:

```bash
export CIPH_PASSWORD=testpassword123
./test_ciph.sh
unset CIPH_PASSWORD
```

The test verifies:

* encryption correctness
* filename metadata recovery
* integrity via SHA‑256

Pull requests that break tests will not be merged.

---

## 🔐 Cryptography Contributions

If your contribution touches cryptographic code:

* ❌ Do not invent new crypto algorithms
* ❌ Do not change parameters without justification
* ❌ Do not remove authentication checks

All cryptography must rely on **libsodium** primitives.

If you are unsure, open a discussion **before** writing code.

---

## 🧹 Code Style

* C code should be clean, minimal, and commented where necessary
* Python code should follow PEP 8
* Avoid unnecessary dependencies
* Keep functions small and focused

---

## 📝 Documentation

If you add or change functionality, update:

* `README.md`
* `SECURITY.md` (if relevant)
* inline comments where appropriate

Documentation changes are highly appreciated.

---

## 🚨 Reporting Security Issues

Please **do not** report security vulnerabilities in public issues.

Follow the instructions in **SECURITY.md** for responsible disclosure.

---

## 📬 Communication

* GitHub Issues — for bugs and feature requests
* Pull Requests — for code changes
* Security issues — see `SECURITY.md`

For private contact:

```
m DOT ankitchaubey AT gmail DOT com
```

---

## ✅ Pull Request Checklist

Before submitting a PR, ensure:

* [ ] Code builds successfully
* [ ] `test_ciph.sh` passes
* [ ] No security regression
* [ ] Documentation updated (if needed)
* [ ] Commit messages are clear

---

## 🙏 Thank You

Your time and effort are appreciated.

By contributing to **ciph**, you help build a safer ecosystem for handling sensitive data.
