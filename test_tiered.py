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
