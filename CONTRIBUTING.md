# Contributing

Thanks for your interest! This project is intentionally small and
dependency-free; contributions that keep it that way are most welcome.

## Ground rules

- **Owner-side only.** Contributions must not turn the toolkit into a remote
  attack tool. Anything that weakens the physical-access requirement (e.g.,
  attempts to bypass the button login) will be rejected.
- **Python stdlib only.** No third-party dependencies in the shipped code
  (test tooling may use the stdlib `unittest` only as well).
- **No third-party router code.** Never include binaries or exploit code from
  other projects; re-implement from first principles and document the idea.

## Development setup

```bash
git clone https://github.com/VulcanusALex/nexxt-one-toolkit.git
cd nexxt-one-toolkit
python -m unittest discover -s tests -v   # run the test suite
./nexxt --help                            # unified CLI
```

## Pull requests

1. Fork, branch, commit with clear messages (English).
2. Keep `python -m py_compile nexxt_toolkit/*.py tools/*.py` and the test
   suite green (CI runs both on Python 3.9 and 3.12).
3. Add tests for new logic, especially anything touching the injection
   command construction or the transfer/bisect logic.
4. Update docs (`docs/`, README) when behavior changes.

## Hardware notes

If you have a NeXXt One on a different firmware version, compatibility
reports are valuable. Run `./nexxt support-bundle`, review `report.json`, and
attach the ZIP to a compatibility issue. Do not paste a session dump or HAR.

## Releasing

1. Bump `__version__` in `nexxt_toolkit/__init__.py` and `version` in
   `pyproject.toml`; update `CHANGELOG.md`.
2. Commit, tag `vX.Y.Z`, push with tags.
3. Create a GitHub Release — the `release` workflow builds the wheel, source
   archive and standalone `nexxt.pyz`, uploads them with `SHA256SUMS`, and
   publishes to PyPI automatically via **trusted publishing** (one-time setup:
   on pypi.org → project → Publishing → add this repo's `release.yml`).
