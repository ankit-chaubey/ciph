from setuptools import setup, find_packages

setup(
    name="ciph",
    version="1.0.0",
    description="Fast, streaming file encryption for large media files and cloud uploads",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
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
