#!/usr/bin/env bash
set -euo pipefail
python -m build
python -m twine check dist/*
python -m pip install --force-reinstall dist/*.whl
python - <<'PY'
import odin_ope, json
print('odin_ope version:', odin_ope.__version__ if hasattr(odin_ope,'__version__') else 'n/a')
print('exports:', sorted([n for n in dir(odin_ope) if not n.startswith('_')])[:15], '...')
PY
