from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext
import subprocess
import os
import sys
import shutil


class BuildCiphExt(build_ext):
    def run(self):
        root = os.path.abspath(os.path.dirname(__file__))

        print("\n🔧 Building native libciph")

        # Clean is best-effort
        try:
            subprocess.check_call(["make", "clean"], cwd=root)
        except Exception:
            pass

        subprocess.check_call(["make"], cwd=root)

        if sys.platform.startswith("linux"):
            libname = "libciph.so"
        elif sys.platform == "darwin":
            libname = "libciph.dylib"
        elif sys.platform.startswith(("win32", "cygwin", "msys")):
            libname = "ciph.dll"
        else:
            raise RuntimeError(f"Unsupported platform: {sys.platform}")

        src = os.path.join(root, libname)
        if not os.path.exists(src):
            raise RuntimeError(f"Native build failed: {libname} not found")

        dst = os.path.join(root, "ciph", "_native")
        os.makedirs(dst, exist_ok=True)
        shutil.copy2(src, os.path.join(dst, libname))

        print(f"✔ Native library installed → ciph/_native/{libname}\n")

        super().run()


# Dummy extension to force build_ext execution
ext_modules = [
    Extension(
        "ciph._build",
        sources=["ciph/_build.c"],
    )
]

setup(

    packages=find_packages(),
    include_package_data=True,

    ext_modules=ext_modules,
    cmdclass={"build_ext": BuildCiphExt},
)
