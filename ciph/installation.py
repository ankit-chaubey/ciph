#!/usr/bin/env python3
"""
ciph — Encryption Engine CLI
© 2026 Ankit Chaubey (@ankit-chaubey)
https://github.com/ankit-chaubey/ciph

Licensed under the Apache License, Version 2.0
https://www.apache.org/licenses/LICENSE-2.0
"""

import sys
import shutil
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[1]        # ← go from ciph/ → repo root
NATIVE_DIR = HERE.parent / "_native"
LIB_NAME = "libciph.so"


def die(msg):
    print(f"ciph setup: {msg}", file=sys.stderr)
    sys.exit(1)


def run(cmd, cwd):
    try:
        subprocess.run(cmd, cwd=cwd, check=True)
    except FileNotFoundError:
        die(f"missing tool: {cmd[0]}")
    except subprocess.CalledProcessError:
        die(f"command failed: {' '.join(cmd)}")


def main():
    makefile = REPO_ROOT / "Makefile"
    if not makefile.exists():
        die("Makefile not found")

    print("🔧 Building native ciph engine")

    run(["make", "clean"], REPO_ROOT)
    run(["make"], REPO_ROOT)

    lib = REPO_ROOT / LIB_NAME
    if not lib.exists():
        die("libciph.so not produced")

    NATIVE_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(lib, NATIVE_DIR / LIB_NAME)

    print("✅ libciph.so installed to ciph/_native")
    print("✔ ciph setup complete")


if __name__ == "__main__":
    main()
