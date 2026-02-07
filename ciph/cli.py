#!/usr/bin/env python3
"""
ciph — Encryption Engine CLI
© 2026 Ankit Chaubey (@ankit-chaubey)
https://github.com/ankit-chaubey/ciph

Licensed under the Apache License, Version 2.0
https://www.apache.org/licenses/LICENSE-2.0
"""

import sys
import os
import getpass
import ctypes
import argparse
from tqdm import tqdm


def _load_lib():
    here = os.path.dirname(__file__)
    return ctypes.CDLL(os.path.join(here, "_native", "libciph.so"))


def _load_or_die():
    try:
        return _load_lib()
    except OSError:
        print("ciph: native library not found", file=sys.stderr)
        print("run: ciph setup", file=sys.stderr)
        sys.exit(1)


LIB = None


def _bind():
    global LIB
    LIB = _load_or_die()

    LIB.ciph_encrypt_stream.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
    ]
    LIB.ciph_encrypt_stream.restype = ctypes.c_int

    LIB.ciph_decrypt_stream.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    LIB.ciph_decrypt_stream.restype = ctypes.c_int

    LIB.ciph_set_chunk_mb.argtypes = [ctypes.c_size_t]
    LIB.ciph_set_chunk_mb.restype = None

    LIB.ciph_strerror.argtypes = [ctypes.c_int]
    LIB.ciph_strerror.restype = ctypes.c_char_p


libc = ctypes.CDLL(None)
fdopen = libc.fdopen
fdopen.argtypes = [ctypes.c_int, ctypes.c_char_p]
fdopen.restype = ctypes.c_void_p


def _usage():
    print(
        "Usage:\n"
        "  ciph setup\n"
        "  ciph encrypt <file> [options]\n"
        "  ciph decrypt <file.ciph> [options]\n\n"
        "Options:\n"
        "  --cipher {aes,chacha}   Cipher selection (default: aes)\n"
        "  -c, --chunk <MB>        Chunk size in MB (default: 4)\n\n"
        "Environment:\n"
        "  CIPH_PASSWORD   Password (non-interactive)\n"
        "  CIPH_CHUNK_MB   Default chunk size\n"
    )


def _password():
    p = os.getenv("CIPH_PASSWORD")
    if not p:
        p = getpass.getpass("Password: ")
    return p.encode()


def _apply_chunk(v):
    if v is not None:
        LIB.ciph_set_chunk_mb(v)
        return
    env = os.getenv("CIPH_CHUNK_MB")
    if env:
        try:
            LIB.ciph_set_chunk_mb(int(env))
        except ValueError:
            pass


def _cfile(pyf, mode):
    fd = os.dup(pyf.fileno())
    return fdopen(fd, mode)


def _die(rc):
    msg = LIB.ciph_strerror(rc).decode(errors="ignore")
    print(f"ciph: {msg}", file=sys.stderr)
    sys.exit(1)


def _cipher(v):
    if v == "chacha":
        return 2
    return 1


def main():
    if len(sys.argv) == 1:
        _usage()
        sys.exit(0)

    if sys.argv[1] == "setup":
        from .installation import main as setup_main
        setup_main()
        return

    ap = argparse.ArgumentParser(prog="ciph", add_help=True)
    ap.add_argument("command", choices=["encrypt", "decrypt"])
    ap.add_argument("file")
    ap.add_argument("-c", "--chunk", type=int)
    ap.add_argument("--cipher", choices=["aes", "chacha"], default="aes")
    args = ap.parse_args()

    _bind()

    if not os.path.exists(args.file):
        print(f"ciph: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    _apply_chunk(args.chunk)
    cipher = _cipher(args.cipher)
    pwd = _password()

    total = os.path.getsize(args.file)

    fin_py = open(args.file, "rb")
    fin = _cfile(fin_py, b"rb")

    name_buf = ctypes.create_string_buffer(256)

    with tqdm(
        total=total,
        unit="B",
        unit_scale=True,
        dynamic_ncols=True,
        desc=args.command.capitalize(),
    ) as bar:

        if args.command == "encrypt":
            out = args.file + ".ciph"
            fout_py = open(out, "wb")
            fout = _cfile(fout_py, b"wb")

            rc = LIB.ciph_encrypt_stream(
                fin,
                fout,
                pwd,
                cipher,
                os.path.basename(args.file).encode(),
            )

            if rc != 0 and cipher == 1:
                fout_py.close()
                os.remove(out)

                fout_py = open(out, "wb")
                fout = _cfile(fout_py, b"wb")

                rc = LIB.ciph_encrypt_stream(
                    fin,
                    fout,
                    pwd,
                    2,
                    os.path.basename(args.file).encode(),
                )

            fout_py.close()

            if rc != 0:
                os.remove(out)
                _die(rc)

            bar.update(total)

        else:
            tmp = ".__ciph_tmp__"
            fout_py = open(tmp, "wb")
            fout = _cfile(fout_py, b"wb")

            rc = LIB.ciph_decrypt_stream(
                fin,
                fout,
                pwd,
                name_buf,
                ctypes.sizeof(name_buf),
            )

            fout_py.close()

            if rc != 0:
                os.remove(tmp)
                _die(rc)

            out = name_buf.value.decode() or "output.dec"
            os.rename(tmp, out)

            bar.update(total)

    fin_py.close()
    print(f"[+] Output → {out}")


if __name__ == "__main__":
    main()
