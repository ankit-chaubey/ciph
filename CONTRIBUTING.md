# Contributing

Security and correctness come before features or speed. If a change weakens security it won't be accepted.

## Setup

```bash
git clone https://github.com/ankit-chaubey/ciph
cd ciph && make && pip install -e .
```

Requirements: Linux/Termux, Python >= 3.8, libsodium, gcc/clang

## Project structure

```
ciph.c           -- crypto core (C / libsodium)
ciph.h           -- public C interface
ciph/cli.py      -- CLI wrapper
ciph/_native/    -- compiled .so
test_ciph.sh     -- integration test
```

Keep crypto logic in C, not Python.

## Testing

Run before any PR:

```bash
export CIPH_PASSWORD=testpassword123
./test_ciph.sh
unset CIPH_PASSWORD
```

PRs that break tests won't be merged.

## Crypto rules

- Don't invent new algorithms
- Don't change KDF parameters without justification
- Don't remove authentication checks
- All crypto must go through libsodium primitives
- If unsure, open a discussion before writing code

## Code style

- C: clean, minimal, comment non-obvious parts
- Python: PEP 8
- No unnecessary dependencies

## Reporting security issues

Don't open a public issue. Email: m.ankitchaubey@gmail.com with subject `SECURITY: ciph vulnerability report`

Response within 72 hours.
