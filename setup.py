from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='stealth25519',
    version='1.0.8',
    description='The Stealth25519 Python package provides functionality for the generation, verification, and signing of stealth addresses using the standard ed25519 algorithm with the ECDH protocol.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[],
    tests_require=[],
    package_data={'': ['LICENSE']},
    include_package_data=True,
    license='MIT',
    project_urls={
        'Source': 'https://github.com/khqnn/stealth-py',
    },
    entry_points={
        'console_scripts': [],
    },
)
