#!/usr/bin/env python3
import sys, os, getpass, ctypes
from tqdm import tqdm

HERE = os.path.dirname(__file__)
LIB = ctypes.CDLL(os.path.join(HERE, "_native", "libciph.so"))

LIB.ciph_encrypt_stream.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_char_p, ctypes.c_int,
    ctypes.c_char_p
]

LIB.ciph_decrypt_stream.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p, ctypes.c_size_t
]

libc = ctypes.CDLL(None)
fdopen = libc.fdopen
fdopen.argtypes = [ctypes.c_int, ctypes.c_char_p]
fdopen.restype = ctypes.c_void_p


def detect_cipher():
    try:
        with open("/proc/cpuinfo") as f:
            if "aes" in f.read().lower():
                return 1
    except Exception:
        pass
    return 2


def get_password():
    pwd = os.getenv("CIPH_PASSWORD")
    if not pwd:
        pwd = getpass.getpass("Password: ")
    return pwd.encode()


def c_file(py_file, mode):
    fd = os.dup(py_file.fileno())   # 🔑 duplicate FD
    return fdopen(fd, mode)


def main():
    if len(sys.argv) < 3:
        print("usage: ciph encrypt|decrypt <file>")
        sys.exit(1)

    cmd, src = sys.argv[1], sys.argv[2]
    password = get_password()
    total_size = os.path.getsize(src)

    fin_py = open(src, "rb")
    fin = c_file(fin_py, b"rb")

    name_buf = ctypes.create_string_buffer(256)

    with tqdm(
        total=total_size,
        unit="B",
        unit_scale=True,
        desc=cmd.capitalize()
    ) as bar:

        if cmd == "encrypt":
            out_name = src + ".ciph"
            fout_py = open(out_name, "wb")
            fout = c_file(fout_py, b"wb")

            LIB.ciph_encrypt_stream(
                fin,
                fout,
                password,
                detect_cipher(),
                os.path.basename(src).encode()
            )

            bar.update(total_size)

        elif cmd == "decrypt":
            tmp_name = ".__tmp__"
            fout_py = open(tmp_name, "wb")
            fout = c_file(fout_py, b"wb")

            res = LIB.ciph_decrypt_stream(
                fin,
                fout,
                password,
                name_buf,
                ctypes.sizeof(name_buf)
            )

            fout_py.close()

            if res != 0:
                os.remove(tmp_name)
                print("ciph: wrong password or corrupted file", file=sys.stderr)
                sys.exit(1)

            out_name = name_buf.value.decode() or "output.dec"
            os.rename(tmp_name, out_name)

            bar.update(total_size)

        else:
            print("usage: ciph encrypt|decrypt <file>")
            sys.exit(1)

    fin_py.close()
    print(f"[+] Output → {out_name}")


if __name__ == "__main__":
    main()
