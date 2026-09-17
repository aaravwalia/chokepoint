# Chokepoint

**Supply-chain risk scored by structural position, not severity.**

Live demo: https://aaravwalia.github.io/chokepoint/

A package with no known vulnerability, sitting beneath 4,000 downstream
packages, maintained by one unpaid person, is a larger risk than a medium CVE
in a leaf. Conventional scanners evaluate packages one at a time and cannot see
this, because the risk does not live in any single package — it lives in the
shape of the graph.

Chokepoint maps that shape, simulates what a compromise would actually reach,
and ranks where a single intervention removes the most exposure.

---

## The finding that motivates it

Running Chokepoint across 892 packages drawn from the npm mainstream:

| | |
|---|---|
| Packages analysed | 892 |
| Dependency edges | 1,528 |
| **Known advisories at resolved versions** | **1** |
| Packages with a single publisher | 270 |

A CVE scanner reports this ecosystem as clean. Meanwhile `has-flag` — six lines
of code, one publisher — sits beneath **2.47 billion weekly downloads**, and
compromising it reaches 10.7% of the tracked ecosystem roots in four hops.

That gap is the product.

---

## What it does

**Blast radius** — everything that transitively depends on a package, weighted
by real weekly download counts.

**Detonate** — simulate a compromise and watch it propagate hop by hop, with
the real paths:

```
has-flag → supports-color → jest-worker → minimizer-webpack-plugin → webpack
has-flag → supports-color → chalk → @jest/types → jest
```

**Chokepoint ranking** — an explicit, published formula rather than a black box:

```
reach = 0.6 · downstream-download percentile + 0.4 · blast-breadth percentile
score = 100 · reach^0.7 · (0.40 + 0.60 · fragility)
```

Reach dominates, because position is the thesis. Fragility modulates: a widely
depended-on package that is robustly maintained is still a chokepoint, just a
safer one.

**Pre-compromise signals** — single-publisher packages, install-time script
execution, long release gaps, deprecation. These are the conditions that
preceded the real supply-chain attacks, and all are computable from registry
metadata before anything happens.

**Single-fix optimiser** — of everything an application pulls in, which one pin
removes the most transitive exposure.

---

## Data

Four public APIs, all free and unauthenticated:

| Source | Used for |
|---|---|
| [deps.dev](https://deps.dev) | resolved transitive dependency graphs |
| [OSV.dev](https://osv.dev) | known vulnerabilities, batched |
| npm registry | publishers, publish timestamps, install scripts |
| npm downloads API | weekly downloads, used to weight reach |

**The reverse index is built here.** deps.dev reports how many packages depend
on X, but not *which* ones — and without the list there are no propagation
paths to show. So the corpus is assembled by fetching forward trees for ~56
ecosystem roots and inverting every edge.

---

## Run it

```bash
pip install -r requirements.txt
python build.py                 # build the corpus (only needed once)
python -m uvicorn chokepoint.app:app --port 8899
```

Then open <http://localhost:8899>.

A prebuilt snapshot ships in `data/ecosystem.json.gz`, so the server runs
without a build step and **without network access**. Verify that:

```bash
python verify.py
```

---

## Layout

```
chokepoint/
  sources.py    cached clients for the four APIs
  graph.py      reverse index, scoring, simulation
  snapshot.py   freeze/load the analysed ecosystem
  app.py        HTTP API
web/index.html  interface
build.py        corpus builder
verify.py       offline + sanity checks
```

---

## Honest limits

- The reverse index covers the corpus we build, not all of npm. Blast radii are
  therefore lower bounds — real-world reach is larger.
- Dependency resolution is version-pinned to what deps.dev resolved; a
  different lockfile yields a different graph.
- Reachability analysis (does the importing code actually call the compromised
  function?) is not implemented. Blast radius is exposure, not proven
  exploitability.
- Fragility signals describe **structural exposure**, never an accusation. A
  solo maintainer is a systemic risk to everyone downstream, not a suspect.
