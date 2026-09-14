"""Freeze a built ecosystem to disk and load it back.

The snapshot is what makes the demo safe: the API loads it in under a second
and never touches the network, so nothing filmed can depend on an API being
up, fast, or reachable from the venue's wifi.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

from .graph import Ecosystem, Node

DATA = Path(__file__).resolve().parent.parent / "data"
SNAPSHOT = DATA / "ecosystem.json.gz"


def save(eco: Ecosystem, path: Path = SNAPSHOT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "roots": eco.roots,
        "forward": {k: sorted(v) for k, v in eco.forward.items() if v},
        "nodes": {
            n.name: {
                "v": sorted(n.versions),
                "dl": n.downloads,
                "m": n.maintainers,
                "vc": n.version_count,
                "lp": n.last_publish,
                "is": n.has_install_script,
                "dep": n.deprecated,
                "lic": n.license,
                "vuln": n.vulns,
                "en": n.enriched,
                "vv": n.vulnerable_versions,
            }
            for n in eco.nodes.values()
        },
    }
    with gzip.open(path, "wt", encoding="utf-8") as f:
        json.dump(payload, f)
    return path


def load(path: Path = SNAPSHOT) -> Ecosystem:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        payload = json.load(f)
    eco = Ecosystem()
    eco.roots = payload["roots"]
    for name, d in payload["nodes"].items():
        eco.nodes[name] = Node(
            name=name,
            versions=set(d["v"]),
            downloads=d["dl"],
            maintainers=d["m"],
            version_count=d["vc"],
            last_publish=d["lp"],
            has_install_script=d["is"],
            deprecated=d["dep"],
            license=d["lic"],
            vulns=d["vuln"],
            enriched=d["en"],
            vulnerable_versions=d.get("vv", []),
        )
    for parent, deps in payload["forward"].items():
        for dep in deps:
            eco.forward[parent].add(dep)
            eco.reverse[dep].add(parent)
    return eco


def exists(path: Path = SNAPSHOT) -> bool:
    return path.exists()
