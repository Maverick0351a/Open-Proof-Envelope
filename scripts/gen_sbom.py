#!/usr/bin/env python
"""Generate a minimal CycloneDX SBOM (JSON) from pyproject.toml.
No external dependencies; uses stdlib tomllib (3.11+).
Outputs to stdout or writes to file if --out provided.
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import re
import sys
import uuid
from typing import Any

try:
    import tomllib  # Python 3.11+
except Exception:  # pragma: no cover
    print("tomllib required (Python 3.11+)", file=sys.stderr)
    raise

LICENSE_ID_MAP = {"Apache-2.0": {"id": "Apache-2.0"}}

SEMVER_PATTERN = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+)(?P<spec>.*)$")


def parse_deps(dep_list: list[str]) -> list[dict[str, Any]]:
    comps = []
    for dep in dep_list:
        # Keep full spec as version field if exact pin, else put in purl qualifiers
        m = SEMVER_PATTERN.match(dep)
        if not m:
            continue
        name = m.group("name")
        spec = m.group("spec") or ""
        component = {
            "type": "library",
            "name": name,
        }
        # If spec is like == or ==version extract version
        if spec.startswith("=="):
            component["version"] = spec[2:]
        else:
            if spec:
                component["properties"] = [{"name": "spec", "value": spec}]
        component["purl"] = f"pkg:pypi/{name}"
        comps.append(component)
    return comps


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="Output file (defaults to stdout)")
    args = ap.parse_args()

    script_dir = (
        pathlib.Path(__file__).resolve().parent.parent
    )  # project root (one level up from scripts)
    pyproject_path = script_dir / "pyproject.toml"
    if not pyproject_path.exists():
        # fallback: walk up
        pyproject_path = pathlib.Path.cwd() / "pyproject.toml"
    pyproject = tomllib.loads(pyproject_path.read_text("utf-8"))
    proj = pyproject.get("project", {})
    name = proj.get("name", "unknown")
    version = proj.get("version", "0.0.0")
    license_obj = proj.get("license", {})
    license_text = None
    if isinstance(license_obj, dict):
        license_text = license_obj.get("text")

    deps = proj.get("dependencies", [])
    optional = proj.get("optional-dependencies", {})
    components = parse_deps(deps)
    for group, dep_list in optional.items():
        group_comps = parse_deps(dep_list)
        for c in group_comps:
            c.setdefault("properties", []).append({"name": "optional-group", "value": group})
        components.extend(group_comps)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "component": {
                "type": "application",
                "name": name,
                "version": version,
                **(
                    {
                        "licenses": [
                            {"license": LICENSE_ID_MAP.get(license_text, {"name": license_text})}
                        ]
                    }
                    if license_text
                    else {}
                ),
            },
        },
        "components": components,
    }

    data = json.dumps(bom, indent=2, sort_keys=True)
    if args.out:
        pathlib.Path(args.out).write_text(data, encoding="utf-8")
    else:
        print(data)


if __name__ == "__main__":  # pragma: no cover
    main()
