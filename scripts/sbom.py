#!/usr/bin/env python3
"""Génère la SBOM CycloneDX 1.5 (JSON) de Keryx depuis requirements.lock (Python) et web/package-lock.json (interface).

Sans dépendance externe ni accès réseau. Usage : python scripts/sbom.py [sortie.json]
[ISO/IEC 27002:2022 8.25, 8.28 ; plan : SBOM CycloneDX à chaque version]
"""
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.search(r'^__version__ = "([^"]+)"', (ROOT / "keryx" / "__init__.py").read_text(), re.M).group(1)


def python_components():
    out = []
    for line in (ROOT / "requirements.lock").read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", line)
        if m:
            out.append({"type": "library", "name": m.group(1), "version": m.group(2),
                        "purl": f"pkg:pypi/{m.group(1).lower()}@{m.group(2)}", "scope": "required"})
    return out


def npm_components():
    lock = json.loads((ROOT / "web" / "package-lock.json").read_text())
    out = []
    for path, meta in lock.get("packages", {}).items():
        if not path or "version" not in meta:
            continue
        name = path.split("node_modules/")[-1]
        comp = {"type": "library", "name": name, "version": meta["version"], "purl": f"pkg:npm/{name.replace('@', '%40', 1) if name.startswith('@') else name}@{meta['version']}",
                "scope": "optional" if meta.get("dev") else "required"}
        if meta.get("integrity"):
            algo, _, b64 = meta["integrity"].partition("-")
            if algo == "sha512":
                import base64
                comp["hashes"] = [{"alg": "SHA-512", "content": base64.b64decode(b64).hex()}]
        out.append(comp)
    return out


def main(argv):
    out = Path(argv[1]) if len(argv) > 1 else ROOT / "sbom.cdx.json"
    comps = python_components() + npm_components()
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
           "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(),
                        "component": {"type": "application", "name": "keryx", "version": VERSION}},
           "components": comps}
    out.write_text(json.dumps(bom, indent=1, ensure_ascii=False))
    print(f"SBOM : {len(comps)} composants -> {out}")


if __name__ == "__main__":
    main(sys.argv)
