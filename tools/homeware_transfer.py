#!/usr/bin/env python3
"""Backward-compatible shim -- use the unified CLI: homeware transfer

Legacy usage: homeware_transfer.py <file> <tag> <target>
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from homeware_toolkit.cli import main  # noqa: E402
if len(sys.argv) == 4 and not sys.argv[1].startswith("-"):
    _, f, tag, target = sys.argv
    sys.exit(main(["transfer", f, target, "--tag", tag]))
sys.exit(main(["transfer"] + sys.argv[1:]))
