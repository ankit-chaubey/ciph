import os
import shutil
import subprocess
from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext


class CiphNative(Extension):
    def __init__(self):
        super().__init__(
            name="ciph._native.libciph",
            sources=[]
        )


class BuildNative(build_ext):
    def run(self):
        self._check_make()
        self._build_ciph()
        super().run()

    def _check_make(self):
        if shutil.which("make") is None:
            raise RuntimeError("make is required to build libciph")

    def _build_ciph(self):
        root = os.path.abspath(os.path.dirname(__file__))
        native_dir = os.path.join(root, "ciph", "_native")
        os.makedirs(native_dir, exist_ok=True)

        print("🔧 Building native libciph")

        subprocess.check_call(["make", "clean"], cwd=root)
        subprocess.check_call(["make"], cwd=root)

        so = os.path.join(root, "libciph.so")
        if not os.path.isfile(so):
            raise RuntimeError("libciph.so was not produced")

        shutil.copy2(so, os.path.join(native_dir, "libciph.so"))

        test = os.path.join(root, "test_ciph.sh")
        if os.path.exists(test):
            shutil.copy2(test, os.path.join(native_dir, "test_ciph.sh"))

        print("✅ libciph installed into ciph/_native")


setup(
    name="ciph",
    version="1.0.0",
    description="High-performance streaming encryption engine",
    packages=find_packages(),
    include_package_data=True,
    ext_modules=[CiphNative()],
    cmdclass={"build_ext": BuildNative},
    entry_points={
        "console_scripts": [
            "ciph=ciph.cli:main"
        ]
    },
    python_requires=">=3.8",
    install_requires=[
        "tqdm>=4.60.0"
    ],
)
