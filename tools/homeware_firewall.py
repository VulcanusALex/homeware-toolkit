#!/usr/bin/env python3
"""Backward-compatible shim -- use the unified CLI: homeware fw"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from homeware_toolkit.cli import main  # noqa: E402
sys.exit(main(["fw"] + sys.argv[1:]))
