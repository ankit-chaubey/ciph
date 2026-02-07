import os
from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext


class CiphNative(Extension):
    def __init__(self):
        super().__init__(
            name="ciph._native.libciph",
            sources=[],
        )


class BuildNative(build_ext):
    def run(self):
        # 🚫 Default: DO NOT build native code during packaging
        if os.environ.get("CIPH_BUILD_NATIVE") != "1":
            print("⚠️  Skipping native libciph build (set CIPH_BUILD_NATIVE=1 to enable)")
            return

        # ⚠️ Only for local dev / manual builds
        self._build_native()

    def _build_native(self):
        import shutil
        import subprocess

        if shutil.which("make") is None:
            raise RuntimeError("make is required to build libciph")

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

        print("✅ libciph installed into ciph/_native")


setup(
    name="ciph",
    version="1.0.0",
    description="Fast, streaming file encryption for large media files and cloud uploads",
    packages=find_packages(),
    include_package_data=False,

    # Stub extension — real build happens at runtime via `ciph setup`
    ext_modules=[CiphNative()],
    cmdclass={"build_ext": BuildNative},

    entry_points={
        "console_scripts": [
            "ciph=ciph.cli:main",
        ]
    },

    python_requires=">=3.8",
    install_requires=[
        "tqdm>=4.60.0",
    ],
)
