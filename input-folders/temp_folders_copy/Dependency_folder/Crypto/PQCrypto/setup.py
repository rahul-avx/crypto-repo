from setuptools import setup, find_packages

setup(
    name="pqcrypto-test",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "liboqs-python>=0.9.0",
        "pqcrypto>=2.8.0",
        "cryptography>=41.0.3",
        "pycryptodome>=3.18.0"
    ],
    extras_require={
        "dev": ["pytest>=7.4.0"]
    }
)
