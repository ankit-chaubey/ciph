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

        try:
            subprocess.check_call(["make", "clean"], cwd=root)
        except Exception:
            pass

        subprocess.check_call(["make"], cwd=root)

        if sys.platform.startswith("linux"):
            libname = "libciph.so"
        elif sys.platform == "darwin":
            libname = "libciph.dylib"
        elif sys.platform.startswith("win"):
            libname = "ciph.dll"
        else:
            raise RuntimeError("Unsupported platform")

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
    Extension(    "ciph._build",    sources=["ciph/_build.c"],)
]

setup(
    name="ciph",
    version="1.2.2",
    description="High-performance streaming encryption engine for large files",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    license="Apache-2.0",
    python_requires=">=3.8",
    packages=find_packages(),
    include_package_data=True,
    install_requires=["tqdm>=4.60.0"],
    entry_points={"console_scripts": ["ciph=ciph.cli:main"]},
    ext_modules=ext_modules,
    cmdclass={"build_ext": BuildCiphExt},
)
