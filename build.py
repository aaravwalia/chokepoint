"""Build the ecosystem graph and freeze it to a snapshot.

    python build.py            # build with defaults
    python build.py --deep 800 # enrich more packages
"""
import argparse, time
from chokepoint.sources import Source
from chokepoint.graph import Ecosystem, DEFAULT_ROOTS
from chokepoint import snapshot

ap = argparse.ArgumentParser()
ap.add_argument("--deep", type=int, default=500)
ap.add_argument("--workers", type=int, default=8)
a = ap.parse_args()

t0 = time.time()
src = Source()
print(f"Building from {len(DEFAULT_ROOTS)} ecosystem roots\n")
eco = Ecosystem().build(src, DEFAULT_ROOTS)
print(f"\nGraph: {eco.stats()}\n")
eco.enrich(src, deep=a.deep, workers=a.workers)
p = snapshot.save(eco)
src.close()

s = eco.stats()
print(f"\n{'='*58}")
print(f"  packages          {s['packages']:>8,}")
print(f"  edges             {s['edges']:>8,}")
print(f"  with known vulns  {s['with_vulns']:>8,}")
print(f"  solo maintainer   {s['solo_maintainer']:>8,}")
print(f"  weekly downloads  {s['total_weekly_downloads']:>8,}")
print(f"  snapshot          {p.stat().st_size/1024:.0f} KB -> {p.name}")
print(f"  http hits/misses  {src.hits}/{src.misses}")
print(f"  elapsed           {time.time()-t0:.1f}s")
print("="*58)
