from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='stealth25519',
    version='1.0.4',
    description='The Stealth25519 Python package provides functionality for the generation, verification, and signing of stealth addresses using the standard ed25519 algorithm with the ECDH protocol.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[],
    tests_require=[],
    entry_points={
        'console_scripts': [],
    },
)
