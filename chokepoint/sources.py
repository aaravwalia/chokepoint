"""Ingestion layer for the four public data sources Chokepoint runs on.

All four are free and unauthenticated:

  deps.dev   resolved transitive dependency graphs, and dependent *counts*
  OSV.dev    known vulnerabilities, batched
  npm registry   maintainer lists and per-version publish timestamps
  npm api        weekly download counts, used to weight downstream reach

Every response is cached to disk. Once a package is cached it is served from
disk forever unless refreshed explicitly, which is what lets the demo run with
the network disconnected.
"""
from __future__ import annotations

import json
import hashlib
import time
from pathlib import Path
from typing import Any, Iterable

import httpx

CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

DEPS_DEV = "https://api.deps.dev"
OSV = "https://api.osv.dev"
NPM_REGISTRY = "https://registry.npmjs.org"
NPM_API = "https://api.npmjs.org"

TIMEOUT = httpx.Timeout(20.0, connect=10.0)


class Offline(RuntimeError):
    """Raised when a value is not cached and network access is disabled."""


class Source:
    """Cached HTTP client.

    Set ``offline=True`` to guarantee no network call is ever made -- used to
    prove before filming that the demo cannot fail live.
    """

    def __init__(self, offline: bool = False, quiet: bool = False):
        self.offline = offline
        self.quiet = quiet
        self.hits = 0
        self.misses = 0
        self._client = httpx.Client(
            timeout=TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": "chokepoint/0.1 (supply-chain risk research)"},
        )

    # ---------- cache plumbing ----------

    def _path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()[:20]
        safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in key)[:60]
        return CACHE_DIR / f"{safe}.{digest}.json"

    def _cached(self, key: str) -> Any | None:
        p = self._path(key)
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))["body"]
            except (json.JSONDecodeError, KeyError):
                return None
        return None

    def _store(self, key: str, body: Any) -> None:
        self._path(key).write_text(
            json.dumps({"key": key, "fetched": time.time(), "body": body}),
            encoding="utf-8",
        )

    def _fetch(self, url: str, post: dict | None = None, attempts: int = 4) -> Any:
        """Fetch with backoff.

        npm's download API rate-limits bursts with 429s. Retrying with a short
        exponential backoff recovers essentially all of them -- during the
        first corpus build roughly 30 scoped packages failed this way and were
        silently scored as zero downloads.
        """
        delay = 0.6
        for attempt in range(1, attempts + 1):
            try:
                r = (
                    self._client.post(url, json=post)
                    if post is not None
                    else self._client.get(url)
                )
                if r.status_code == 404:
                    return None
                if r.status_code == 429 or r.status_code >= 500:
                    if attempt < attempts:
                        time.sleep(delay)
                        delay *= 2
                        continue
                    if not self.quiet:
                        print(f"  ! HTTP {r.status_code} after {attempt} tries: {url}")
                    return None
                r.raise_for_status()
                return r.json()
            except httpx.HTTPError as e:
                if attempt < attempts:
                    time.sleep(delay)
                    delay *= 2
                    continue
                if not self.quiet:
                    print(f"  ! {type(e).__name__}: {url}")
                return None
        return None

    def _get(self, key: str, url: str, *, post: dict | None = None,
             transform=None) -> Any:
        """Cache-first fetch.

        ``transform`` is applied *before* caching. npm registry documents can
        run to several megabytes; we only ever need a handful of fields, so
        trimming first keeps the on-disk cache small enough to commit.
        """
        hit = self._cached(key)
        if hit is not None:
            self.hits += 1
            return hit
        if self.offline:
            raise Offline(f"not cached and offline: {key}")
        self.misses += 1
        body = self._fetch(url, post)
        if body is None:
            return None
        if transform is not None:
            body = transform(body)
        self._store(key, body)
        return body

    # ---------- npm registry ----------

    @staticmethod
    def _trim_registry_doc(raw: dict) -> dict:
        """Reduce a full npm registry document to the fields we score on.

        The full document carries every version's complete manifest. We need
        maintainers, publish times and install-script presence, so we discard
        the rest before it ever touches disk.
        """
        times = raw.get("time", {}) or {}
        versions = raw.get("versions", {}) or {}
        return {
            "name": raw.get("name"),
            "latest": (raw.get("dist-tags") or {}).get("latest"),
            "maintainers": [m.get("name") for m in raw.get("maintainers", []) or []],
            "version_count": len(versions),
            "times": {k: v for k, v in times.items()
                      if k not in ("created", "modified")},
            "created": times.get("created"),
            "modified": times.get("modified"),
            "deprecated": any("deprecated" in (v or {}) for v in versions.values()),
            "has_install_script": any(
                bool(set((v.get("scripts") or {}).keys())
                     & {"preinstall", "install", "postinstall"})
                for v in versions.values()
            ),
            "license": raw.get("license") if isinstance(raw.get("license"), str) else None,
        }

    def npm_meta(self, name: str) -> dict | None:
        """Maintainers, version count and publish timestamps.

        The full registry document is required -- ``maintainers`` and ``time``
        are absent from the abbreviated form -- but only the trimmed result is
        cached.
        """
        return self._get(f"npmmeta:{name}", f"{NPM_REGISTRY}/{name}",
                         transform=self._trim_registry_doc)

    def npm_downloads(self, name: str) -> int:
        """Weekly downloads. Used to weight how much reach a node really has."""
        raw = self._get(
            f"npmdl:{name}", f"{NPM_API}/downloads/point/last-week/{name}"
        )
        return int((raw or {}).get("downloads", 0) or 0)

    def npm_downloads_bulk(self, names: list[str]) -> dict[str, int]:
        """Weekly downloads for many packages at once.

        The npm bulk endpoint takes up to 128 comma-separated names but rejects
        scoped packages (``@scope/name``), so those fall back to single lookups.
        """
        out: dict[str, int] = {}
        plain = [n for n in names if not n.startswith("@")]
        scoped = [n for n in names if n.startswith("@")]

        CHUNK = 100
        for i in range(0, len(plain), CHUNK):
            chunk = plain[i : i + CHUNK]
            key = "npmdlbulk:" + hashlib.sha256(
                ",".join(sorted(chunk)).encode()).hexdigest()[:24]
            raw = self._get(
                key, f"{NPM_API}/downloads/point/last-week/{','.join(chunk)}"
            ) or {}
            for nm in chunk:
                entry = raw.get(nm) or {}
                out[nm] = int(entry.get("downloads", 0) or 0) if entry else 0

        # Scoped packages must be fetched one at a time; pace them so the
        # burst does not trip npm's rate limiter.
        for j, nm in enumerate(scoped):
            if j and j % 20 == 0:
                time.sleep(1.0)
            out[nm] = self.npm_downloads(nm)
        return out

    # ---------- deps.dev ----------

    def dependencies(self, name: str, version: str, system: str = "npm") -> dict | None:
        """Full *resolved transitive* dependency graph in a single call.

        Returns deps.dev's node/edge form: nodes carry versionKey, edges are
        index pairs into that node list.
        """
        url = (
            f"{DEPS_DEV}/v3/systems/{system}/packages/"
            f"{name.replace('/', '%2F')}/versions/{version}:dependencies"
        )
        return self._get(f"deps:{system}:{name}@{version}", url)

    def dependent_count(self, name: str, version: str, system: str = "npm") -> dict:
        """Global dependent counts. Note: counts only -- deps.dev does not
        expose the dependent *list*, which is why we build our own reverse
        index in graph.py. Used here as an independent corroborating signal.
        """
        url = (
            f"{DEPS_DEV}/v3alpha/systems/{system}/packages/"
            f"{name.replace('/', '%2F')}/versions/{version}:dependents"
        )
        raw = self._get(f"dependents:{system}:{name}@{version}", url) or {}
        return {
            "total": raw.get("dependentCount", 0),
            "direct": raw.get("directDependentCount", 0),
            "indirect": raw.get("indirectDependentCount", 0),
        }

    # ---------- OSV ----------

    def vulns_batch(self, pkgs: Iterable[tuple[str, str]],
                    ecosystem: str = "npm") -> dict[str, list[str]]:
        """Batched vulnerability lookup. Returns {"name@version": [ids]}."""
        pkgs = list(pkgs)
        out: dict[str, list[str]] = {}
        CHUNK = 100
        for i in range(0, len(pkgs), CHUNK):
            chunk = pkgs[i : i + CHUNK]
            key = "osv:" + hashlib.sha256(
                json.dumps(chunk, sort_keys=True).encode()
            ).hexdigest()[:24]
            body = {
                "queries": [
                    {"package": {"ecosystem": ecosystem, "name": n}, "version": v}
                    for n, v in chunk
                ]
            }
            raw = self._get(key, f"{OSV}/v1/querybatch", post=body) or {}
            for (n, v), res in zip(chunk, raw.get("results", [])):
                ids = [x.get("id") for x in (res or {}).get("vulns", []) or []]
                if ids:
                    out[f"{n}@{v}"] = ids
        return out

    # ---------- convenience ----------

    def latest_version(self, name: str) -> str | None:
        meta = self.npm_meta(name)
        return meta.get("latest") if meta else None

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
