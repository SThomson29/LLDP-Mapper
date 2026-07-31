#!/usr/bin/env python3
"""Large-estate readability: tooltips, block grouping, routing hubs."""
import itertools
import xml.etree.ElementTree as ET

from lldp_mapper import (Device, Edge, RoutingAdj, Topology, _layout,
                         to_drawio_xml)

# 2 cores, 3 agg pairs, 12 dual-homed access = 20 switches
topo = Topology()
K = {}
def sw(name):
    K[name] = "aa:%02x:00:00:00:%02x" % (len(K) // 250, len(K) % 250)
    topo.upsert_device(Device(key=K[name], hostname=name, is_switch=True))
def link(a, b, pa="x", pb="y"):
    topo.add_edge(Edge(a_key=K[a], a_port=pa, b_key=K[b], b_port=pb))

for n in ("core-01", "core-02"):
    sw(n)
link("core-01", "core-02", "1/1/49", "1/1/49")
pods = {}
for p in (1, 2, 3):
    a1, a2 = f"agg-{p}a", f"agg-{p}b"
    sw(a1); sw(a2)
    link(a1, a2)
    for agg in (a1, a2):
        link("core-01", agg); link("core-02", agg)
    pods[p] = []
    for i in range(1, 5):
        acc = f"acc-{p}{i}"
        sw(acc)
        link(a1, acc); link(a2, acc)     # dual-homed to own pair only
        pods[p].append(acc)

pairs = [(K["core-01"], K["core-02"]),
         (K["agg-1a"], K["agg-1b"]),
         (K["agg-2a"], K["agg-2b"]),
         (K["agg-3a"], K["agg-3b"])]

pos = _layout(topo, pairs)
y = {n: pos[K[n]][1] for n in K}
assert y["core-01"] < y["agg-1a"] < y["acc-11"]
assert len({round(v) for v in y.values()}) == 3
# block grouping: each pod's access spans sit under their own agg pair,
# and pods don't interleave horizontally
spans = {}
for p, accs in pods.items():
    xs = [pos[K[a]][0] for a in accs]
    spans[p] = (min(xs), max(xs))
    agg_mid = (pos[K[f"agg-{p}a"]][0] + pos[K[f"agg-{p}b"]][0]) / 2
    assert min(xs) - 200 <= agg_mid <= max(xs) + 200, (p, agg_mid, spans[p])
ordered = sorted(spans.values())
for (l1, r1), (l2, r2) in zip(ordered, ordered[1:]):
    assert r1 < l2, (ordered)          # gap between blocks, no interleave
print("block grouping OK (pods contiguous, under own agg pair, gapped)")

# iBGP mesh across cores+aggs (8 members) + one OSPF area across all
adjs = []
mesh = ["core-01", "core-02"] + [f"agg-{p}{s}" for p in (1, 2, 3)
                                 for s in "ab"]
for a, b in itertools.combinations(mesh, 2):
    adjs.append(RoutingAdj(protocol="bgp", vrf="default",
                           a_key=K[a], b_key=K[b],
                           detail="iBGP AS 65001", state="Established"))
for acc in [n for n in K if n.startswith("acc-")]:
    adjs.append(RoutingAdj(protocol="ospf", vrf="default",
                           a_key=K[acc], b_key=K["core-01"],
                           detail="area 0.0.0.0", state="FULL"))

xml = to_drawio_xml(topo, routing_adjs=adjs, vsx_pairs=pairs)
root = ET.fromstring(xml)

# tooltip mode: 20 switches > 15 -> physical edges carry tooltips,
# no printed end labels
phys = root.findall("diagram")[0]
objs = phys.findall(".//object")
assert objs and all(o.get("tooltip") for o in objs)
assert any("1/1/49" in o.get("tooltip", "") for o in objs)
end_labels = [c for c in phys.findall(".//mxCell")
              if c.get("connectable") == "0"]
assert not end_labels
print(f"tooltip mode OK ({len(objs)} edges with hover detail, "
      "no printed labels)")

# routing hubs: iBGP mesh of 8 -> 1 hub + 8 spokes (not 28 edges);
# OSPF area of 13 members -> 1 hub + 13 spokes
rtg = root.findall("diagram")[1]
cells = rtg.findall(".//mxCell")
hubs = [c for c in cells if "ellipse" in (c.get("style") or "")]
assert len(hubs) == 2, len(hubs)
hub_labels = {c.get("value", "").split("\n")[0] for c in hubs}
assert "iBGP AS 65001" in hub_labels
assert any(l.startswith("OSPF area") for l in hub_labels)
edges = [c for c in cells if c.get("edge")]
assert len(edges) == 8 + 13, len(edges)   # spokes only, no mesh
print(f"routing hubs OK (2 hubs, {len(edges)} spokes vs "
      f"{28 + 13} pairwise edges)")

# --detail-labels forces printed labels back on
xml2 = to_drawio_xml(topo, vsx_pairs=pairs, force_detail=True)
phys2 = ET.fromstring(xml2).findall("diagram")[0]
assert [c for c in phys2.findall(".//mxCell")
        if c.get("connectable") == "0"]
print("--detail-labels override OK")
