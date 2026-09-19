from setuptools import setup, find_packages

setup(
    name="alpha-wireless",
    version="1.0.0",
    description="Termux-Native Rootless Wireless Observation & Environmental Awareness Platform",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "alpha = alpha.cli:main",
        ],
    },
)
