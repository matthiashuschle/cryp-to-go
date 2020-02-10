from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='cryp-to-go',
    version='0.1.1',
    packages=find_packages(),
    install_requires=['pynacl>=1.3.0', 'cryptography>=2.8', 'peewee'],
    url='https://github.com/matthiashuschle/cryp-to-go',
    license='MIT',
    python_requires=">=3.6",
    author='Matthias Huschle',
    author_email='matthiashuschle@gmail.com',
    description='easy to use high-level crypto library for encrypted data storage/exchange',
    long_description=long_description,
    long_description_content_type="text/markdown",
    entry_points={
        'console_scripts': [
            'cryp-to-go = cryp_to_go.cli:main'
        ]
    }
)
