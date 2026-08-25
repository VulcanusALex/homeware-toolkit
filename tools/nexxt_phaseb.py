#!/usr/bin/env python3
"""Backward-compatible shim -- use the unified CLI: nexxt verify"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from nexxt_toolkit.cli import main  # noqa: E402
sys.exit(main(["verify"] + sys.argv[1:]))
