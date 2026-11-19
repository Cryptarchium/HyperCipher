from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="pyouro",
    version="1.2.7",
    description="A cryptographic trust anchor and DRM framework for Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Gabriele",
    author_email="gabriele.locascio99@gmail.com",
    url="https://github.com/Gabro29/PyOuro",
    project_urls={
        "Source Code": "https://github.com/Gabro29/PyOuro",
        "Bug Tracker": "https://github.com/Gabro29/PyOuro/issues",
        "Documentation": "https://github.com/Gabro29/PyOuro#readme",
    },
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
        "toml>=0.10.2",
        "pyyaml>=6.0",
        "keyring>=24.0.0",
        "cython>=3.0.0",
        "setuptools>=68.0.0",
        "pyinstaller>=6.0.0",
    ],
    extras_require={
        # Install with: pip install pyouro[standalone]
        "standalone": [
            "pyinstaller>=6.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "pyouro=pyouro.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Build Tools",
    ],
    python_requires=">=3.8",
)
