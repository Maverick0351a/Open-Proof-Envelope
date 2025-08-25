Param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
python -m build
python -m twine check dist/*
pip install --force-reinstall (Get-ChildItem dist -Filter *.whl | Select-Object -First 1).FullName
python - <<'PY'
import odin_ope, json
print('odin_ope version:', getattr(odin_ope, '__version__', 'n/a'))
print('has MESSAGE_FORMAT_VERSION:', hasattr(odin_ope, 'MESSAGE_FORMAT_VERSION'))
PY
