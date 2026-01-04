#!/usr/bin/env python3
"""Minimal setup.py for backwards compatibility.

Modern Python packaging uses pyproject.toml. This file exists only for
compatibility with older tools that don't support PEP 517/518/621.

For installation, prefer:
    pip install .
    pip install -e .
    pip install -e ".[dev]"
"""

from setuptools import setup

if __name__ == "__main__":
    setup()
