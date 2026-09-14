"""Reverse dependency index, chokepoint scoring, and compromise simulation.

The central problem this module solves: deps.dev will tell you how many
packages depend on X, but not *which ones*. Without that list you cannot show
a propagation path, and a propagation path is the entire point.

So we invert it ourselves. Fetch the resolved transitive graph for a corpus of
ecosystem roots -- each call returns a whole tree -- union the edges, then flip
every edge. The result is a real reverse index with real paths.
"""
from __future__ import annotations

import math
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from .sources import Source


def semver_key(v: str) -> tuple:
    """Sort key for version strings.

    Plain ``sorted()`` compares lexically, which ranks "9.0.0" above "10.0.0"
    and silently made vulnerability lookups query the wrong version. Release
    versions sort above prereleases of the same number.
    """
    core, _, pre = v.partition("-")
    parts = []
    for p in core.split(".")[:3]:
        digits = "".join(c for c in p if c.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return (*parts, 0 if pre else 1, pre)


def latest_of(versions) -> str | None:
    vs = [v for v in versions if v]
    return max(vs, key=semver_key) if vs else None

# Ecosystem roots. Each returns its full resolved tree in one call, so ~40
# requests yield a few thousand packages with genuine edges between them.
DEFAULT_ROOTS = [
    "express", "react-dom", "vue", "webpack", "vite", "eslint", "jest",
    "axios", "typescript", "rollup", "prettier", "next", "nodemon",
    "mocha", "chai", "lodash", "moment", "commander", "yargs", "chalk",
    "socket.io", "mongoose", "sequelize", "knex", "pg", "mysql2",
    "redis", "dotenv", "cors", "helmet", "passport", "jsonwebtoken",
    "bcrypt", "multer", "sharp", "puppeteer", "cheerio", "node-fetch",
    "esbuild", "postcss", "tailwindcss", "sass", "babel-loader",
    "@babel/core", "ts-node", "rimraf", "glob", "inquirer", "ora",
    "winston", "pino", "joi", "zod", "uuid", "date-fns", "ramda",
]


@dataclass
class Node:
    name: str
    versions: set[str] = field(default_factory=set)
    downloads: int = 0
    maintainers: list[str] = field(default_factory=list)
    version_count: int = 0
    last_publish: str | None = None
    has_install_script: bool = False
    deprecated: bool = False
    license: str | None = None
    vulns: list[str] = field(default_factory=list)
    global_dependents: int = 0
    enriched: bool = False
    vulnerable_versions: list[str] = field(default_factory=list)


class Ecosystem:
    """A slice of npm, held as a forward graph plus its inversion."""

    def __init__(self) -> None:
        self.forward: dict[str, set[str]] = defaultdict(set)   # pkg -> its deps
        self.reverse: dict[str, set[str]] = defaultdict(set)   # pkg -> its dependents
        self.nodes: dict[str, Node] = {}
        self.roots: list[str] = []

    # ---------- construction ----------

    def _node(self, name: str) -> Node:
        if name not in self.nodes:
            self.nodes[name] = Node(name=name)
        return self.nodes[name]

    def ingest_tree(self, tree: dict) -> None:
        """Fold one deps.dev resolved tree into the graph."""
        if not tree or not tree.get("nodes"):
            return
        names = []
        for n in tree["nodes"]:
            vk = n.get("versionKey", {})
            nm = vk.get("name", "")
            names.append(nm)
            if nm:
                self._node(nm).versions.add(vk.get("version", ""))
        for e in tree.get("edges", []):
            a, b = names[e["fromNode"]], names[e["toNode"]]
            if a and b and a != b:
                self.forward[a].add(b)
                self.reverse[b].add(a)

    def build(self, src: Source, roots: Iterable[str] | None = None,
              progress: bool = True) -> "Ecosystem":
        roots = list(roots or DEFAULT_ROOTS)
        self.roots = roots
        for i, r in enumerate(roots, 1):
            v = src.latest_version(r)
            if not v:
                if progress:
                    print(f"  [{i:>2}/{len(roots)}] {r:<22} unresolved")
                continue
            tree = src.dependencies(r, v)
            before = len(self.nodes)
            self.ingest_tree(tree)
            if progress:
                n = len(tree.get("nodes", [])) if tree else 0
                print(f"  [{i:>2}/{len(roots)}] {r:<22} tree={n:>4}  "
                      f"total={len(self.nodes):>5} (+{len(self.nodes)-before})")
        return self

    def enrich(self, src: Source, deep: int = 500, workers: int = 8,
               progress: bool = True) -> "Ecosystem":
        """Attach download, maintainer and vulnerability metadata.

        Three passes, ordered by cost:

        1. Downloads for every package, via the npm bulk endpoint (~20 calls
           for a few thousand packages). Needed everywhere, because reach is
           download-weighted.
        2. Full registry metadata for the ``deep`` most structurally important
           packages only. Fragility is only meaningful for nodes that carry
           real downstream weight, and this is one request per package.
        3. Vulnerabilities for everything, batched 100 at a time.
        """
        names = sorted(self.nodes)

        if progress:
            print(f"  [1/3] downloads for {len(names)} packages (bulk)")
        for nm, dl in src.npm_downloads_bulk(names).items():
            if nm in self.nodes:
                self.nodes[nm].downloads = dl

        important = sorted(
            names, key=lambda n: (len(self.reverse.get(n, ())),
                                  self.nodes[n].downloads), reverse=True
        )[:deep]
        if progress:
            print(f"  [2/3] registry metadata for top {len(important)} by dependents")

        def fetch(nm: str):
            return nm, src.npm_meta(nm)

        done = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for nm, meta in pool.map(fetch, important):
                done += 1
                if not meta:
                    continue
                node = self.nodes[nm]
                node.maintainers = meta.get("maintainers") or []
                node.version_count = meta.get("version_count", 0)
                node.has_install_script = bool(meta.get("has_install_script"))
                node.deprecated = bool(meta.get("deprecated"))
                node.license = meta.get("license")
                node.enriched = True
                times = meta.get("times") or {}
                if times:
                    node.last_publish = max(times.values())
                if progress and done % 100 == 0:
                    print(f"        {done}/{len(important)}")

        # Query every *resolved* version seen across the corpus, not just the
        # newest. The newest release of a package is almost always patched --
        # the risk lives in the versions real projects actually resolve to.
        pairs = [(n.name, v) for n in self.nodes.values()
                 for v in n.versions if v]
        if progress:
            print(f"  [3/3] vulnerabilities for {len(pairs)} resolved "
                  f"name@version pairs (batched)")
        for key, ids in src.vulns_batch(pairs).items():
            nm, _, ver = key.rpartition("@")
            node = self.nodes.get(nm)
            if node:
                node.vulns = sorted(set(node.vulns) | set(ids))
                node.vulnerable_versions = sorted(
                    set(node.vulnerable_versions) | {ver})
        return self

    # ---------- analysis ----------

    def blast_radius(self, pkg: str) -> set[str]:
        """Every package that transitively depends on ``pkg``."""
        seen: set[str] = set()
        q = deque([pkg])
        while q:
            cur = q.popleft()
            for parent in self.reverse.get(cur, ()):
                if parent not in seen:
                    seen.add(parent)
                    q.append(parent)
        return seen

    def blast_levels(self, pkg: str, max_depth: int = 12) -> dict[str, int]:
        """Blast radius annotated with hop distance -- drives the animation."""
        level = {pkg: 0}
        q = deque([pkg])
        while q:
            cur = q.popleft()
            if level[cur] >= max_depth:
                continue
            for parent in self.reverse.get(cur, ()):
                if parent not in level:
                    level[parent] = level[cur] + 1
                    q.append(parent)
        return level

    def path_to(self, src_pkg: str, dst_pkg: str) -> list[str]:
        """Shortest propagation path from a compromised package up to a
        dependent, e.g. ['color-convert', 'chalk', 'eslint']."""
        if src_pkg == dst_pkg:
            return [src_pkg]
        prev: dict[str, str] = {src_pkg: ""}
        q = deque([src_pkg])
        while q:
            cur = q.popleft()
            for parent in self.reverse.get(cur, ()):
                if parent not in prev:
                    prev[parent] = cur
                    if parent == dst_pkg:
                        path, n = [], parent
                        while n:
                            path.append(n)
                            n = prev[n]
                        return list(reversed(path))
                    q.append(parent)
        return []

    def downstream_downloads(self, pkg: str) -> int:
        """Weekly downloads summed across everything downstream. This is the
        honest measure of reach -- a package is only as important as what
        actually depends on it."""
        return sum(self.nodes[p].downloads for p in self.blast_radius(pkg)
                   if p in self.nodes)

    # ---------- scoring ----------

    def fragility(self, pkg: str) -> tuple[float, list[str]]:
        """Maintenance fragility in 0..1, with the reasons that produced it.

        These are the conditions that preceded the real supply-chain attacks --
        a solo maintainer, install-time code execution, an abandoned package
        that is still everywhere. They describe *structural exposure*, never an
        accusation against any maintainer.
        """
        n = self.nodes.get(pkg)
        if not n:
            return 0.0, []
        if not n.enriched:
            # Metadata was never fetched for this node, so we genuinely do not
            # know. Report that honestly rather than inventing a risk signal.
            return 0.0, ["fragility not assessed (metadata not fetched)"]
        score, why = 0.0, []

        m = len(n.maintainers)
        if m == 1:
            score += 0.40
            why.append("single point of maintenance (1 publisher)")
        elif m == 2:
            score += 0.20
            why.append("only 2 publishers")
        elif m == 0:
            score += 0.25
            why.append("no maintainer metadata")

        if n.has_install_script:
            score += 0.25
            why.append("runs install-time scripts (arbitrary code on install)")

        if n.last_publish:
            try:
                dt = datetime.fromisoformat(n.last_publish.replace("Z", "+00:00"))
                years = (datetime.now(timezone.utc) - dt).days / 365.25
                if years >= 3:
                    score += 0.25
                    why.append(f"no release in {years:.1f} years")
                elif years >= 1.5:
                    score += 0.12
                    why.append(f"last release {years:.1f} years ago")
            except ValueError:
                pass

        if n.deprecated:
            score += 0.10
            why.append("deprecated versions published")
        if not n.license:
            score += 0.05
            why.append("no declared license")

        return min(score, 1.0), why

    def calibrate(self) -> "Ecosystem":
        """Precompute corpus-wide reach distributions.

        An absolute log scale saturates: every hub package lands between 0.88
        and 0.94 and the ranking stops discriminating. Scoring reach as a
        *percentile within this ecosystem* restores the spread and states the
        honest claim -- "high reach relative to the corpus we measured" rather
        than a false absolute.
        """
        self._radius_cache = {p: self.blast_radius(p) for p in self.nodes}
        self._dd_cache = {
            p: sum(self.nodes[q].downloads for q in r if q in self.nodes)
            for p, r in self._radius_cache.items()
        }
        self._dd_sorted = sorted(self._dd_cache.values())
        self._bc_sorted = sorted(len(r) for r in self._radius_cache.values())
        return self

    @staticmethod
    def _pct(sorted_vals: list, v) -> float:
        """Fraction of the corpus at or below ``v``."""
        if not sorted_vals:
            return 0.0
        lo, hi = 0, len(sorted_vals)
        while lo < hi:
            mid = (lo + hi) // 2
            if sorted_vals[mid] <= v:
                lo = mid + 1
            else:
                hi = mid
        return lo / len(sorted_vals)

    def chokepoint_score(self, pkg: str) -> dict:
        """The headline metric.

            reach      = 0.6 * downstream-download percentile
                       + 0.4 * blast-breadth percentile
            fragility  = maintenance exposure, 0..1
            score      = 100 * reach^0.7 * (0.40 + 0.60 * fragility)

        Reach dominates, because position in the graph is the thesis.
        Fragility modulates: a widely-depended-on package that is robustly
        maintained is still a chokepoint, just a safer one.
        """
        if not hasattr(self, "_radius_cache"):
            self.calibrate()
        radius = self._radius_cache.get(pkg, self.blast_radius(pkg))
        dd = self._dd_cache.get(pkg, 0)
        reach = (0.6 * self._pct(self._dd_sorted, dd)
                 + 0.4 * self._pct(self._bc_sorted, len(radius)))
        frag, why = self.fragility(pkg)
        score = 100.0 * (reach ** 0.7) * (0.40 + 0.60 * frag)
        n = self.nodes.get(pkg)
        return {
            "package": pkg,
            "score": round(score, 1),
            "reach": round(reach, 3),
            "fragility": round(frag, 3),
            "reasons": why,
            "blast_count": len(radius),
            "downstream_downloads": dd,
            "direct_dependents": len(self.reverse.get(pkg, ())),
            "own_downloads": n.downloads if n else 0,
            "maintainers": len(n.maintainers) if n else 0,
            "vulns": n.vulns if n else [],
            "last_publish": n.last_publish if n else None,
        }

    def ranking(self, limit: int = 40) -> list[dict]:
        scored = [self.chokepoint_score(p) for p in self.nodes]
        scored.sort(key=lambda d: d["score"], reverse=True)
        return scored[:limit]

    # ---------- simulation ----------

    def detonate(self, pkg: str, max_depth: int = 12) -> dict:
        """Simulate compromise of ``pkg`` and report what falls."""
        levels = self.blast_levels(pkg, max_depth)
        affected = {k: v for k, v in levels.items() if k != pkg}
        by_level: dict[int, list[str]] = defaultdict(list)
        for name, lv in affected.items():
            by_level[lv].append(name)
        hit_roots = [r for r in self.roots if r in affected]
        exposed_dl = sum(self.nodes[p].downloads for p in affected
                         if p in self.nodes)
        samples = []
        for r in hit_roots[:6]:
            p = self.path_to(pkg, r)
            if p:
                samples.append({"target": r, "path": p, "hops": len(p) - 1})
        return {
            "origin": pkg,
            "affected_count": len(affected),
            "affected_downloads_per_week": exposed_dl,
            "max_depth_reached": max(affected.values()) if affected else 0,
            "by_level": {str(k): sorted(v) for k, v in sorted(by_level.items())},
            "ecosystem_roots_hit": hit_roots,
            "roots_total": len(self.roots),
            "root_coverage_pct": round(
                100.0 * len(hit_roots) / max(len(self.roots), 1), 1),
            "sample_paths": samples,
        }

    def best_intervention(self, target: str, candidates: int = 300) -> list[dict]:
        """Which single package, if pinned or vendored, removes the most
        downstream exposure for ``target``?

        For each package in target's dependency cone, we remove it and measure
        how much of target's reachable-dependency set disappears.
        """
        cone = self._dependency_cone(target)
        cone.discard(target)
        if not cone:
            return []
        baseline = len(cone)
        ranked = []
        for c in sorted(cone, key=lambda p: -len(self.blast_radius(p)))[:candidates]:
            removed = self._dependency_cone(target, blocked={c})
            removed.discard(target)
            saved = baseline - len(removed)
            if saved > 0:
                frag, why = self.fragility(c)
                ranked.append({
                    "pin": c,
                    "removes": saved,
                    "pct_of_cone": round(100.0 * saved / baseline, 1),
                    "fragility": round(frag, 3),
                    "reasons": why,
                })
        ranked.sort(key=lambda d: d["removes"], reverse=True)
        return ranked[:10]

    def _dependency_cone(self, pkg: str, blocked: set[str] | None = None) -> set[str]:
        """Everything ``pkg`` transitively depends on, optionally cutting nodes."""
        blocked = blocked or set()
        seen, q = {pkg}, deque([pkg])
        while q:
            cur = q.popleft()
            for dep in self.forward.get(cur, ()):
                if dep in blocked or dep in seen:
                    continue
                seen.add(dep)
                q.append(dep)
        return seen

    # ---------- stats ----------

    def stats(self) -> dict:
        edges = sum(len(v) for v in self.forward.values())
        return {
            "packages": len(self.nodes),
            "edges": edges,
            "roots": len(self.roots),
            "with_vulns": sum(1 for n in self.nodes.values() if n.vulns),
            "solo_maintainer": sum(1 for n in self.nodes.values()
                                   if len(n.maintainers) == 1),
            "total_weekly_downloads": sum(n.downloads for n in self.nodes.values()),
        }
