#!/usr/bin/env python3
"""Tests for the tiered (hierarchical) layout on a 3-tier campus."""
from lldp_mapper import Device, Edge, Topology, _layout

def sw(key, host):
    return Device(key=key, hostname=host, mgmt_ip="", platform="",
                  is_switch=True)

topo = Topology()
K = {}
for i, name in enumerate(["core-01", "core-02", "agg-01", "agg-02",
                          "acc-01", "acc-02", "acc-03", "acc-04"]):
    K[name] = f"aa:00:00:00:00:0{i}"
    topo.upsert_device(sw(K[name], name))
ap = Device(key="ee:00:00:00:00:01", hostname="ap-1", is_switch=False)
topo.upsert_device(ap)

def link(a, pa, b, pb):
    topo.add_edge(Edge(a_key=K.get(a, a), a_port=pa,
                       b_key=K.get(b, b), b_port=pb))

# core VSX ISL + full mesh core<->agg, aggs feed two access each
link("core-01", "1/1/49", "core-02", "1/1/49")
for agg in ("agg-01", "agg-02"):
    link("core-01", "1/1/1", agg, "1/1/51")
    link("core-02", "1/1/1", agg, "1/1/52")
link("agg-01", "1/1/1", "acc-01", "1/1/51")
link("agg-01", "1/1/2", "acc-02", "1/1/51")
link("agg-02", "1/1/1", "acc-03", "1/1/51")
link("agg-02", "1/1/2", "acc-04", "1/1/51")
topo.add_edge(Edge(a_key=K["acc-01"], a_port="1/1/10",
                   b_key=ap.key, b_port="eth0"))

pairs = [(K["core-01"], K["core-02"])]
pos = _layout(topo, pairs)   # tiered is the default

y = {n: pos[K[n]][1] for n in K}
# strict tier rows: cores above aggs above access
assert y["core-01"] == y["core-02"] < y["agg-01"] == y["agg-02"] \
    < y["acc-01"] == y["acc-04"], y
# VSX pair adjacent on the top row
dx = abs(pos[K["core-01"]][0] - pos[K["core-02"]][0])
assert dx < 400, dx
# endpoint sits below its access switch
assert pos[ap.key][1] > y["acc-01"]
# access under its own agg: acc-01/02 nearer agg-01's x than agg-02's
for acc, own, other in (("acc-01", "agg-01", "agg-02"),
                        ("acc-04", "agg-02", "agg-01")):
    d_own = abs(pos[K[acc]][0] - pos[K[own]][0])
    d_other = abs(pos[K[acc]][0] - pos[K[other]][0])
    assert d_own < d_other, (acc, d_own, d_other)
print("tiered layout OK (3 rows, VSX adjacent, endpoints below, "
      "access under own agg)")

# --core hint overrides detection: pin acc-01 as 'core'
pos2 = _layout(topo, pairs, "tiered", ["acc-01"])
assert pos2[K["acc-01"]][1] < pos2[K["agg-01"]][1] < pos2[K["core-01"]][1]
print("--core hint OK (pinned switch takes the top tier)")

# circle mode still available
posc = _layout(topo, pairs, "circle")
assert len(posc) == len(pos)
print("circle fallback OK")

# --- REGRESSION: dual-homed 3-tier (the real-world shape that broke) ---------
topo2 = Topology()
K2 = {}
for i, name in enumerate(["core-01", "core-02", "agg-01", "agg-02",
                          "acc-01", "acc-02", "acc-03", "acc-04"]):
    K2[name] = f"bb:00:00:00:00:0{i}"
    topo2.upsert_device(sw(K2[name], name))

def link2(a, b):
    topo2.add_edge(Edge(a_key=K2[a], a_port="x", b_key=K2[b], b_port="y"))

link2("core-01", "core-02")
for agg in ("agg-01", "agg-02"):
    link2("core-01", agg); link2("core-02", agg)
for acc in ("acc-01", "acc-02", "acc-03", "acc-04"):
    link2("agg-01", acc); link2("agg-02", acc)   # dual-homed access

pos2t = _layout(topo2, [(K2["core-01"], K2["core-02"])])
y2 = {n: pos2t[K2[n]][1] for n in K2}
rows = sorted({round(v) for v in y2.values()})
assert len(rows) == 3, (rows, y2)
assert y2["core-01"] == y2["core-02"] < y2["agg-01"] == y2["agg-02"] \
    < y2["acc-01"] == y2["acc-04"], y2
print("dual-homed 3-tier OK (3 rows despite diameter-2 graph)")

# collapsed core (2-tier, dual-homed access straight to core pair)
topo3 = Topology()
K3 = {}
for i, name in enumerate(["core-01", "core-02", "acc-01", "acc-02",
                          "acc-03"]):
    K3[name] = f"cc:00:00:00:00:0{i}"
    topo3.upsert_device(sw(K3[name], name))

def link3(a, b):
    topo3.add_edge(Edge(a_key=K3[a], a_port="x", b_key=K3[b], b_port="y"))

link3("core-01", "core-02")
for acc in ("acc-01", "acc-02", "acc-03"):
    link3("core-01", acc); link3("core-02", acc)
pos3 = _layout(topo3, [(K3["core-01"], K3["core-02"])])
assert pos3[K3["core-01"]][1] < pos3[K3["acc-01"]][1]
assert len({round(pos3[K3[n]][1]) for n in K3}) == 2
print("collapsed-core 2-tier OK")

# ---------------------------------------------------------------------------
# REGRESSIONS: row ordering (see git history — these both failed before the
# primary-parent / hostname-order fix)
# ---------------------------------------------------------------------------
def _build(names, macs, links, pairs):
    topo, K = Topology(), {}
    for n in names:
        K[n] = macs[n]
        topo.upsert_device(Device(key=K[n], hostname=n, is_switch=True))
    for a, pa, b, pb in links:
        topo.add_edge(Edge(a_key=K[a], a_port=pa, b_key=K[b], b_port=pb))
    return K, _layout(topo, [(K[x], K[y]) for x, y in pairs])

# --- REGRESSION: VSX member order must follow hostname, not chassis MAC ------
# core-01 is deliberately given the HIGHER chassis MAC. Real chassis MACs
# bear no relation to hostnames, so a fixture numbered in hostname order
# cannot catch this.
names = ["core-01", "core-02", "acc-01", "acc-02"]
macs = {"core-01": "bb:00:00:00:00:01",   # higher MAC, lower hostname
        "core-02": "aa:00:00:00:00:02",
        "acc-01": "cc:00:00:00:00:01",
        "acc-02": "cc:00:00:00:00:02"}
links = [("core-01", "1/1/49", "core-02", "1/1/49"),
         ("core-01", "1/1/1", "acc-01", "1/1/51"),
         ("core-02", "1/1/1", "acc-01", "1/1/52"),
         ("core-01", "1/1/2", "acc-02", "1/1/51"),
         ("core-02", "1/1/2", "acc-02", "1/1/52")]
K, pos = _build(names, macs, links, [("core-01", "core-02")])
assert pos[K["core-01"]][0] < pos[K["core-02"]][0], \
    ("VSX members ordered by MAC, not hostname",
     pos[K["core-01"]][0], pos[K["core-02"]][0])
print("VSX member order OK (-01 left of -02 regardless of chassis MAC)")

# --- REGRESSION: a child homed only to the SECONDARY must not be ranked
# --- against the primary's port numbers.
names = ["core-01", "core-02", "acc-01", "acc-02", "acc-03", "acc-04"]
macs = {n: "dd:00:00:00:00:0%d" % i for i, n in enumerate(names)}
links = [("core-01", "1/1/49", "core-02", "1/1/49"),
         ("core-01", "1/1/1", "acc-01", "1/1/51"),
         ("core-02", "1/1/11", "acc-01", "1/1/52"),
         ("core-01", "1/1/2", "acc-02", "1/1/51"),
         ("core-02", "1/1/12", "acc-02", "1/1/52"),
         ("core-01", "1/1/3", "acc-03", "1/1/51"),
         ("core-02", "1/1/13", "acc-03", "1/1/52"),
         # acc-04 single-homed to the SECONDARY, low port number
         ("core-02", "1/1/1", "acc-04", "1/1/51")]
K, pos = _build(names, macs, links, [("core-01", "core-02")])
order = sorted(["acc-01", "acc-02", "acc-03", "acc-04"],
               key=lambda n: pos[K[n]][0])
assert order == ["acc-01", "acc-02", "acc-03", "acc-04"], order
print("secondary-only child OK (sorts after primary-homed, not by its port)")
