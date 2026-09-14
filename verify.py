"""Verification: the demo must work offline, and the ranking must be sane.

    python verify.py
"""
import socket, sys

from chokepoint import snapshot

# Block the network *after* imports -- ssl subclasses socket.socket at import.
class _Blocked(socket.socket):
    def connect(self, *a, **k): raise OSError("network disabled")
    def connect_ex(self, *a, **k): raise OSError("network disabled")
socket.socket = _Blocked
socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(
    OSError("network disabled"))

fails = []
def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{'  -- ' + detail if detail else ''}")
    if not ok:
        fails.append(label)

print("\nOffline demo path (sockets blocked)\n" + "-" * 52)
eco = snapshot.load().calibrate()
s = eco.stats()
check("snapshot loads", s["packages"] > 100, f"{s['packages']} packages")
check("graph has edges", s["edges"] > 500, f"{s['edges']} edges")

rank = eco.ranking(25)
check("ranking populated", len(rank) == 25)
check("scores are spread", rank[0]["score"] - rank[-1]["score"] > 5,
      f"{rank[0]['score']:.1f} .. {rank[-1]['score']:.1f}")

names = [r["package"] for r in rank]
known = {"graceful-fs", "glob", "has-flag", "chalk", "inherits", "cross-spawn",
         "color-convert", "minimatch", "lru-cache", "supports-color"}
hit = known & set(names)
check("surfaces real infrastructure", len(hit) >= 3, ", ".join(sorted(hit)))

print("\nSimulation\n" + "-" * 52)
d = eco.detonate("has-flag")
check("detonate propagates", d["affected_count"] > 10,
      f"{d['affected_count']} packages, {d['affected_downloads_per_week']/1e9:.2f}B dl/wk")
check("propagation paths resolve", len(d["sample_paths"]) > 0,
      " -> ".join(d["sample_paths"][0]["path"]) if d["sample_paths"] else "none")
check("roots_total reported", d.get("roots_total", 0) > 0, str(d.get("roots_total")))

fix = eco.best_intervention("eslint")
check("optimiser returns options", len(fix) > 0,
      f"pin {fix[0]['pin']} removes {fix[0]['removes']}" if fix else "none")

print("\nHonesty checks\n" + "-" * 52)
unenriched = next((n for n in eco.nodes.values() if not n.enriched), None)
if unenriched:
    f, why = eco.fragility(unenriched.name)
    check("un-enriched nodes report unknown, not risk",
          f == 0.0 and "not assessed" in why[0], unenriched.name)
else:
    check("un-enriched nodes report unknown, not risk", True, "all enriched")

from chokepoint.graph import latest_of
check("semver sorts numerically", latest_of(["9.0.0", "10.0.0"]) == "10.0.0")

print("\n" + "=" * 52)
print("ALL CHECKS PASSED" if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
