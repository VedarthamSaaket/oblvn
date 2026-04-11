from setuptools import setup, find_packages

setup(
    name="oblvn",
    version="1.0.0",
    description="Secure Data Obliteration Platform",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.11",
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "oblvn=run:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
)
