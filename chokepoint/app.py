"""HTTP API over a frozen ecosystem snapshot.

Serves from the snapshot only -- no request ever touches an upstream API, so
the demo behaves identically on the venue's wifi and on a plane.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import snapshot
from .graph import Ecosystem

WEB = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(title="Chokepoint", version="0.1.0",
              description="Supply-chain risk by structural position.")

ECO: Ecosystem | None = None


def eco() -> Ecosystem:
    global ECO
    if ECO is None:
        if not snapshot.exists():
            raise HTTPException(
                503, "No snapshot. Run `python build.py` first.")
        ECO = snapshot.load().calibrate()
    return ECO


@app.get("/api/stats")
def stats():
    e = eco()
    s = e.stats()
    s["note"] = (
        f"{s['with_vulns']} of {s['packages']} packages carry a known "
        f"advisory at their resolved version. A CVE scanner would call this "
        f"ecosystem clean."
    )
    return s


@app.get("/api/search")
def search(q: str = Query(..., min_length=1), limit: int = 12):
    e = eco()
    ql = q.lower()
    exact = [n for n in e.nodes if n.lower() == ql]
    starts = sorted(n for n in e.nodes
                    if n.lower().startswith(ql) and n not in exact)
    contains = sorted(n for n in e.nodes
                      if ql in n.lower() and n not in exact and n not in starts)
    return {"results": (exact + starts + contains)[:limit]}


@app.get("/api/ranking")
def ranking(limit: int = 40):
    return {"ranking": eco().ranking(limit)}


@app.get("/api/package/{name:path}")
def package(name: str):
    e = eco()
    if name not in e.nodes:
        raise HTTPException(404, f"{name} is not in this ecosystem snapshot")
    n = e.nodes[name]
    score = e.chokepoint_score(name)
    score.update({
        "dependencies": sorted(e.forward.get(name, ())),
        "dependents": sorted(e.reverse.get(name, ())),
        "version_count": n.version_count,
        "maintainer_names": n.maintainers,
        "has_install_script": n.has_install_script,
        "license": n.license,
        "enriched": n.enriched,
        "vulnerable_versions": n.vulnerable_versions,
        "resolved_versions": sorted(n.versions),
    })
    return score


@app.get("/api/detonate/{name:path}")
def detonate(name: str, max_depth: int = 12):
    e = eco()
    if name not in e.nodes:
        raise HTTPException(404, f"{name} is not in this ecosystem snapshot")
    return e.detonate(name, max_depth)


@app.get("/api/intervention/{name:path}")
def intervention(name: str):
    e = eco()
    if name not in e.nodes:
        raise HTTPException(404, f"{name} is not in this ecosystem snapshot")
    return {"target": name, "options": e.best_intervention(name)}


@app.get("/api/graph/{name:path}")
def subgraph(name: str, max_depth: int = 4, cap: int = 260):
    """Blast-radius subgraph for rendering: the origin plus everything that
    depends on it, out to ``max_depth`` hops."""
    e = eco()
    if name not in e.nodes:
        raise HTTPException(404, f"{name} is not in this ecosystem snapshot")
    levels = e.blast_levels(name, max_depth)
    keep = sorted(levels, key=lambda p: (levels[p], -e.nodes[p].downloads))[:cap]
    keepset = set(keep)
    nodes = []
    for p in keep:
        n = e.nodes[p]
        frag, _ = e.fragility(p)
        nodes.append({
            "id": p,
            "level": levels[p],
            "downloads": n.downloads,
            "maintainers": len(n.maintainers),
            "fragility": round(frag, 3),
            "score": e.chokepoint_score(p)["score"],
            "is_root": p in e.roots,
            "origin": p == name,
        })
    edges = [{"source": dep, "target": parent}
             for parent in keepset
             for dep in e.forward.get(parent, ())
             if dep in keepset]
    return {"origin": name, "nodes": nodes, "edges": edges,
            "truncated": len(levels) > len(keep)}


@app.get("/api/cone/{name:path}")
def cone(name: str, cap: int = 260):
    """What ``name`` depends on, transitively.

    Application roots have no dependents inside the corpus, so a blast radius
    is empty for them and tells you nothing. Their exposure runs the other
    way -- down into what they consume -- and that is what this returns.
    """
    e = eco()
    if name not in e.nodes:
        raise HTTPException(404, f"{name} is not in this ecosystem snapshot")
    members = e._dependency_cone(name)
    depth = {name: 0}
    frontier = [name]
    while frontier:
        nxt = []
        for p in frontier:
            for d in e.forward.get(p, ()):
                if d in members and d not in depth:
                    depth[d] = depth[p] + 1
                    nxt.append(d)
        frontier = nxt
    keep = sorted(members, key=lambda p: (depth.get(p, 99),
                                          -e.nodes[p].downloads))[:cap]
    keepset = set(keep)
    nodes = []
    for p in keep:
        n = e.nodes[p]
        frag, _ = e.fragility(p)
        nodes.append({
            "id": p, "level": depth.get(p, 0), "downloads": n.downloads,
            "maintainers": len(n.maintainers), "fragility": round(frag, 3),
            "score": e.chokepoint_score(p)["score"],
            "is_root": p in e.roots, "origin": p == name,
        })
    edges = [{"source": dep, "target": parent}
             for parent in keepset
             for dep in e.forward.get(parent, ())
             if dep in keepset]
    return {"origin": name, "mode": "cone", "nodes": nodes, "edges": edges,
            "truncated": len(members) > len(keep)}


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


if (WEB).exists():
    app.mount("/static", StaticFiles(directory=WEB), name="static")
