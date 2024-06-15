import codecs
import os
import re
import sys

from shutil import rmtree
from setuptools import setup, find_packages

NAME = "crashtalk"
META_PATH = os.path.join("src", "crashd", "__init__.py")
PACKAGES = find_packages(where="src")
CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "Natural Language :: English",
    "License :: OSI Approved :: GNU Affero General Public License v3",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
]

setup(
    name=NAME,
    version="0.1.0",
    packages=PACKAGES,
    package_dir={"": "src"},
    include_package_data=True,
    package_data={
        "": ["*.txt", "*.html"]
    },
    classifiers=CLASSIFIERS,
    python_requires=">=3.6.0",
    install_requires=[
       "zelos>=0.2.0",
       "pyelftools==0.28",
       "prettytable>=2.0.0",
       "pandas>=1.1.5",
    ],
   setup_requires=["wheel"],
   entry_points={
            "zelos.plugins": [
                "asan=crashd.asan",
                "dataflow=crashd.taint",
                "ida=crashd.static_analysis",
            ],
    },
)
