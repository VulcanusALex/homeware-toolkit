#!/usr/bin/env python3
"""Build standalone installers for macOS and Windows.

This script produces:

- ``dist/home_gateway.pyz`` — the dependency-free zipapp (existing release artifact).
- ``dist/home-gateway-toolkit-<version>-macos.app.zip`` — macOS .app bundle
  (when run on macOS with PyInstaller installed).
- ``dist/home-gateway-toolkit-<version>-win64.spec`` — PyInstaller spec for the
  Windows .exe, meant to be built on a Windows runner or CI.

Usage:

    python tools/build_installer.py

Requirements for macOS app bundling:

    pip install pyinstaller

The Windows spec can be built locally on Windows with:

    pyinstaller dist/home-gateway-toolkit-X.Y.Z-win64.spec
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import zipapp
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build" / "installer"


def _run(cmd: list[str], **kwargs) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, check=True, **kwargs)


def get_version() -> str:
    """Read version from the package without importing side effects."""
    init = (PROJECT_ROOT / "home_gateway_toolkit" / "__init__.py").read_text()
    for line in init.splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip('"\'')
    raise RuntimeError("cannot find __version__")


def build_pyz(version: str) -> Path:
    """Build the standalone zipapp."""
    DIST_DIR.mkdir(exist_ok=True)
    pyz = DIST_DIR / "home_gateway.pyz"
    # Build into a temporary directory so we can include package data.
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    build_pkg = BUILD_DIR / "home_gateway_toolkit"
    build_pkg.mkdir(parents=True)

    src_pkg = PROJECT_ROOT / "home_gateway_toolkit"
    for item in src_pkg.iterdir():
        if item.is_file():
            shutil.copy2(item, build_pkg)
        elif item.is_dir() and item.name != "__pycache__":
            shutil.copytree(item, build_pkg / item.name)

    # Entry point shim.
    main_py = BUILD_DIR / "__main__.py"
    main_py.write_text(
        "from home_gateway_toolkit.cli import main\n"
        "import sys\n"
        "sys.exit(main())\n"
    )

    zipapp.create_archive(BUILD_DIR, pyz, interpreter="/usr/bin/env python3")
    print(f"[build] {pyz}")
    return pyz


def build_macos_app(version: str, pyz: Path) -> Path | None:
    """Build a macOS .app bundle using PyInstaller."""
    if platform.system() != "Darwin":
        print("[build] skipping macOS .app (not running on macOS)")
        return None

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("[build] PyInstaller not installed; skipping macOS .app")
        print("        install with: pip install pyinstaller")
        return None

    app_name = "home-gateway"
    spec_dir = BUILD_DIR / "pyinstaller"
    spec_dir.mkdir(parents=True, exist_ok=True)

    # PyInstaller needs a real Python script entry point, not a .pyz.
    entry = spec_dir / "nexxt_entry.py"
    entry.write_text(
        "# Auto-generated entry point for PyInstaller\n"
        "from home_gateway_toolkit.cli import main\n"
        "import sys\n"
        "sys.exit(main())\n"
    )

    dist_app = DIST_DIR / f"home-gateway-toolkit-{version}-macos.app"
    if dist_app.exists():
        shutil.rmtree(dist_app)

    _run([
        sys.executable, "-m", "PyInstaller",
        "--name", app_name,
        "--onedir",          # .app bundles must be directories on macOS
        "--windowed",
        "--distpath", str(DIST_DIR),
        "--workpath", str(spec_dir / "work"),
        "--specpath", str(spec_dir),
        "--clean",
        "--noconfirm",
        str(entry),
    ], cwd=PROJECT_ROOT)

    built_app = DIST_DIR / f"{app_name}.app"
    if not built_app.exists():
        print("[build] PyInstaller did not produce .app")
        return None

    built_app.rename(dist_app)
    zip_path = DIST_DIR / f"home-gateway-toolkit-{version}-macos.app.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in dist_app.rglob("*"):
            zf.write(path, path.relative_to(DIST_DIR))
    print(f"[build] {zip_path}")
    return zip_path


def write_windows_spec(version: str) -> Path:
    """Generate a PyInstaller spec file for Windows builds."""
    spec = DIST_DIR / f"home-gateway-toolkit-{version}-win64.spec"
    entry = BUILD_DIR / "pyinstaller" / "nexxt_entry.py"
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text(
        "# Auto-generated entry point for PyInstaller\n"
        "from home_gateway_toolkit.cli import main\n"
        "import sys\n"
        "sys.exit(main())\n"
    )
    spec_content = f'''# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for home-gateway-toolkit v{version}
# Build on Windows with: pyinstaller "{spec.name}"

a = Analysis(
    [{entry.as_posix()!r}],
    pathexx=[{PROJECT_ROOT.as_posix()!r}],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='home-gateway',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
'''
    spec.write_text(spec_content)
    print(f"[build] {spec}")
    return spec


def main() -> int:
    version = get_version()
    print(f"[build] home-gateway-toolkit {version}")

    DIST_DIR.mkdir(exist_ok=True)
    pyz = build_pyz(version)
    build_macos_app(version, pyz)
    write_windows_spec(version)

    print("[build] done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
