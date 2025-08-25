# Releasing odin-ope

## Prerequisites
- Up-to-date `CHANGELOG.md`
- Clean `main` (all tests green, coverage >= threshold)
- `PYPI_API_TOKEN` secret configured in GitHub repository settings

## Versioning
Semantic Versioning. Before 1.0.0, minor increments may include breaking changes (document them clearly).

## Steps
1. Decide new version: update `project.version` in `pyproject.toml`.
2. Update `CHANGELOG.md` replacing `Unreleased` with the new version & date.
3. Commit: `git commit -am "Release vX.Y.Z"`.
4. Tag: `git tag -s vX.Y.Z -m "vX.Y.Z"` (use `-s` if you have a GPG key; else omit).
5. Push: `git push && git push --tags`.
6. GitHub Action will run lint, type-check, tests, build, SBOM generation, provenance attestation, and publish to PyPI if on a tagged commit.
7. Download and inspect the `sbom` artifact (CycloneDX) and verify build provenance attestation.
8. Draft a GitHub Release referencing CHANGELOG notes (link to advisory if security-related).

## Dry Run (Local)
```
python -m venv .venv
.venv/Scripts/activate  # Windows: .venv\Scripts\Activate.ps1
pip install --upgrade build twine
python -m build
python -m twine check dist/*
python scripts/gen_sbom.py --out sbom.json
mypy src/odin_ope
ruff check src/odin_ope
black --check src/odin_ope
```

## Post-Release
- Bump version to next dev (optional, e.g. 0.9.1.dev0)
- Add new `Unreleased` section to `CHANGELOG.md`

## Revoking a Release
If a critical issue is found:
1. Yank on PyPI (if appropriate) or publish a hotfix version.
2. Document in CHANGELOG with a warning.
