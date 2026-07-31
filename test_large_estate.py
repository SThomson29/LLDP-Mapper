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

xml = to_drawio_xml(topo, routing_adjs=adjs, vsx_pairs=pairs,
                    split="never")
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
xml2 = to_drawio_xml(topo, vsx_pairs=pairs, force_detail=True,
                     split="never")
phys2 = ET.fromstring(xml2).findall("diagram")[0]
assert [c for c in phys2.findall(".//mxCell")
        if c.get("connectable") == "0"]
print("--detail-labels override OK")

# --- area split (the default for this estate size) ---------------------------
from lldp_mapper import L3Segment, classify_scopes

info = classify_scopes(topo, pairs)
assert info.splittable() and len(info.block_label) == 3
assert set(info.block_label.values()) == {"agg-1", "agg-2", "agg-3"}
assert info.tier[K["core-01"]] == 0 and info.tier[K["acc-31"]] == 2
assert info.block[K["acc-31"]] == info.block[K["agg-3a"]]
print("scope classification OK (3 blocks, common-prefix names)")

# p2p L3: a /31 inside block 1 and a /31 from agg to core
segs = [
    L3Segment(vrf="default", network="10.255.1.0/31",
              members={K["agg-1a"]: "1/1/20 · 10.255.1.0",
                       K["acc-11"]: "1/1/48 · 10.255.1.1"}),
    L3Segment(vrf="default", network="10.254.0.0/31",
              members={K["core-01"]: "1/1/30 · 10.254.0.0",
                       K["agg-2a"]: "1/1/47 · 10.254.0.1"}),
]
sxml = to_drawio_xml(topo, l3_segments=segs, routing_adjs=adjs,
                     vsx_pairs=pairs)   # auto -> split
sroot = ET.fromstring(sxml)
names = [d.get("name") for d in sroot.findall("diagram")]
assert names[0] == "Overview"
for want in ("Core-Agg L1", "agg-1 L1", "agg-2 L1", "agg-3 L1",
             "Core L3", "Core-Agg L3", "agg-1 L3"):
    assert want in names, (want, names)
assert "Physical" not in names          # flat pages replaced
# area grouping: agg-1's pages are adjacent
i1 = names.index("agg-1 L1")
assert names[i1 + 1] == "agg-1 L3"      # no L2 data in this fixture
print(f"area split OK ({len(names)} tabs: {', '.join(names[:4])}, ...)")

# Overview: 2 cores + 3 block nodes, aggregated '2 links' uplink edges
ov = sroot.findall("diagram")[0]
ovc = ov.findall(".//mxCell")
blocknodes = [c for c in ovc if "agg / " in (c.get("value") or "")]
assert len(blocknodes) == 3
assert any("2 agg / 4 access" in (c.get("value") or "") for c in blocknodes)
agg_edges = [c for c in ovc if (c.get("value") or "").endswith("links")]
assert len(agg_edges) == 6              # 2 cores x 3 blocks
assert all(c.get("value") == "2 links" for c in agg_edges)
print("overview OK (cores + 3 block nodes, aggregated uplinks)")

# Block Routed page: the intra-block /31 and the pair's iBGP, small
# enough for printed detail; the core<->agg /31 lands on Core/Agg page
def page_named(n):
    return next(d for d in sroot.findall("diagram") if d.get("name") == n)
b1 = page_named("agg-1 L3")
vals = " ".join(c.get("value") or "" for c in b1.findall(".//mxCell"))
assert "10.255.1.0/31" in vals and "10.254.0.0/31" not in vals
ca = page_named("Core-Agg L3")
cav = " ".join(c.get("value") or "" for c in ca.findall(".//mxCell"))
assert "10.254.0.0/31" in cav
core_rt = page_named("Core L3")
crv = " ".join(c.get("value") or "" for c in core_rt.findall(".//mxCell"))
assert "iBGP AS 65001" in crv
print("routed scoping OK (p2p /31s land on the right area pages)")

# --- L1 core-agg page carries the full core<->dist cabling -------------------
ca_l1 = page_named("Core-Agg L1")
ca_nodes = [c.get("value") or "" for c in ca_l1.findall(".//mxCell")
            if c.get("vertex") == "1" and c.get("connectable") != "0"]
hosts = {v.split("\n")[0] for v in ca_nodes if v and v != "VSX"}
assert hosts == {"core-01", "core-02", "agg-1a", "agg-1b", "agg-2a",
                 "agg-2b", "agg-3a", "agg-3b"}, hosts
# core<->agg links present: 12 uplinks + 1 ISL + 3 pair links
ca_edges = [c for c in ca_l1.findall(".//mxCell") if c.get("edge")] + \
           [c for c in ca_l1.findall(".//object")]
assert len(ca_edges) == 16, len(ca_edges)
print("Core-Agg L1 OK (cores + all agg pairs, full uplink cabling)")

# --- port-number ordering: children follow parent interface numbers ----------
from lldp_mapper import Device as _D, Edge as _E, Topology as _T
pt = _T()
km = {}
for i, n in enumerate(["core-01", "sw-zulu", "sw-alpha", "sw-mike"]):
    km[n] = f"dd:00:00:00:00:0{i}"
    pt.upsert_device(_D(key=km[n], hostname=n, is_switch=True))
# patching order deliberately disagrees with alphabetical order
pt.add_edge(_E(a_key=km["core-01"], a_port="1/1/1",
               b_key=km["sw-zulu"], b_port="1/1/51"))
pt.add_edge(_E(a_key=km["core-01"], a_port="1/1/2",
               b_key=km["sw-alpha"], b_port="1/1/51"))
pt.add_edge(_E(a_key=km["core-01"], a_port="1/1/10",
               b_key=km["sw-mike"], b_port="1/1/51"))
ppos = _layout(pt, [])
xs = [ppos[km[n]][0] for n in ("sw-zulu", "sw-alpha", "sw-mike")]
assert xs[0] < xs[1] < xs[2], xs   # 1/1/1 < 1/1/2 < 1/1/10, not A-Z
print("port ordering OK (1/1/1, 1/1/2, 1/1/10 left to right)")

# --- down-SVI fallback: unfiltered re-fetch recovers the address -------------
from lldp_mapper import AosCxRest

class SviFake(AosCxRest):
    calls = []
    def __init__(self):
        self.host = "10.0.0.9"
    def get(self, path, params=None):
        SviFake.calls.append((path, bool(params and "attributes"
                                         in params)))
        if path == "/system/interfaces/*":
            return {"vlan50": {"vlan_mode": None, "vlan_tag": None,
                               "vlan_trunks": None, "ip4_address": None,
                               "vrf": None},
                    "vlan10": {"vlan_mode": None, "vlan_tag": None,
                               "vlan_trunks": None,
                               "ip4_address": "10.10.0.1/24",
                               "vrf": None}}
        if path == "/system/interfaces/vlan50":
            return {"ip4_address": "10.50.0.1/24", "vlan_mode": None,
                    "vlan_tag": None, "vlan_trunks": None, "vrf": None}
        raise AssertionError(path)

det = SviFake().interface_details()
assert det["vlan50"].ip4 == ["10.50.0.1/24"]      # recovered
assert det["vlan10"].ip4 == ["10.10.0.1/24"]      # untouched
# exactly one extra unfiltered fetch, only for the empty SVI
extra = [p for p, filt in SviFake.calls
         if p == "/system/interfaces/vlan50"]
assert len(extra) == 1
print("down-SVI fallback OK (address recovered via unfiltered re-fetch)")

# --- crossed patching: primary-parent port ordering --------------------------
xt = _T()
xk = {}
for i, n in enumerate(["par-01", "par-02", "child-x", "child-y"]):
    xk[n] = f"ee:00:00:00:00:1{i}"
    xt.upsert_device(_D(key=xk[n], hostname=n, is_switch=True))
xt.add_edge(_E(a_key=xk["par-01"], a_port="1/1/49",
               b_key=xk["par-02"], b_port="1/1/49"))
# child-x: par-01 port 1/1/2, but par-02 port 1/1/1 (crossed)
xt.add_edge(_E(a_key=xk["par-01"], a_port="1/1/2",
               b_key=xk["child-x"], b_port="1/1/51"))
xt.add_edge(_E(a_key=xk["par-02"], a_port="1/1/1",
               b_key=xk["child-x"], b_port="1/1/52"))
# child-y: par-01 port 1/1/1, par-02 port 1/1/2
xt.add_edge(_E(a_key=xk["par-01"], a_port="1/1/1",
               b_key=xk["child-y"], b_port="1/1/51"))
xt.add_edge(_E(a_key=xk["par-02"], a_port="1/1/2",
               b_key=xk["child-y"], b_port="1/1/52"))
xpos = _layout(xt, [(xk["par-01"], xk["par-02"])])
# primary parent is par-01: its 1/1/1 (child-y) must sort left of 1/1/2
assert xpos[xk["child-y"]][0] < xpos[xk["child-x"]][0], (
    xpos[xk["child-y"]][0], xpos[xk["child-x"]][0])
print("crossed-patching ordering OK (primary parent's ports decide)")

# --- p2p merge: subnet + OSPF adjacency render as ONE edge -------------------
merge_segs = [L3Segment(vrf="default", network="10.255.1.0/31",
                        members={K["agg-1a"]: "1/1/20 · 10.255.1.0",
                                 K["acc-11"]: "1/1/48 · 10.255.1.1"})]
merge_adjs = [a for a in adjs] + [
    __import__("lldp_mapper").RoutingAdj(
        protocol="ospf", vrf="default", a_key=K["agg-1a"],
        b_key=K["acc-11"], detail="area 0.0.0.0", state="FULL")]
mxml = to_drawio_xml(topo, l3_segments=merge_segs,
                     routing_adjs=merge_adjs, vsx_pairs=pairs)
mroot = ET.fromstring(mxml)
mb1 = next(d for d in mroot.findall("diagram")
           if d.get("name") == "agg-1 L3")
mcells = list(mb1.iter())
medges = [c for c in mcells if c.get("edge")]
# page carries the merged /31 plus the agg pair's iBGP: exactly 2 edges,
# and the /31 pair (agg-1a <-> acc-11) has ONE edge, carrying both the
# subnet and the OSPF state — the adjacency wasn't drawn in parallel.
assert len(medges) == 2, len(medges)
node_of = {c.get("id"): (c.get("value") or "").split("\n")[0]
           for c in mcells if c.get("vertex") == "1"}
pair_edges = [c for c in medges
              if {node_of.get(c.get("source")),
                  node_of.get(c.get("target"))} == {"agg-1a", "acc-11"}]
assert len(pair_edges) == 1, len(pair_edges)
lbl = pair_edges[0].get("value") or ""
assert "10.255.1.0/31" in lbl and "OSPF FULL" in lbl, lbl
print("p2p merge OK (one edge per /31: subnet + OSPF FULL combined)")

# --- REGRESSION: the firmware combination that broke the field run -----------
# wildcard rejected with 404 AND unknown attributes rejected with 400:
# core collection must survive untouched, AG degrades to N/A.
import requests as _rq
from lldp_mapper import AosCxRest as _ACR

class _Resp:
    def __init__(self, code): self.status_code = code
def _err(code):
    e = _rq.HTTPError(str(code)); e.response = _Resp(code); return e

class BreakFw(_ACR):
    def __init__(self): self.host = "sim-broken"
    def get(self, path, params=None):
        attrs = (params or {}).get("attributes", "")
        if "vsx_virtual_ip4" in attrs:
            raise _err(400)                    # unknown attribute
        if path == "/system/interfaces/*":
            raise _err(404)                    # wildcard unsupported
        if path == "/system/interfaces":
            return {"1/1/1": "u", "vlan10": "u"}
        if path.startswith("/system/interfaces/"):
            name = path.rsplit("/", 1)[-1]
            if name == "vlan10":
                return {"ip4_address": "10.10.0.1/24", "vlan_mode": None,
                        "vlan_tag": None, "vlan_trunks": None, "vrf": None}
            return {"ip4_address": None, "vlan_mode": "access",
                    "vlan_tag": {"20": "u"}, "vlan_trunks": None,
                    "vrf": None}
        raise AssertionError(path)

bdet = BreakFw().interface_details()
assert len(bdet) == 2, bdet
assert bdet["vlan10"].ip4 == ["10.10.0.1/24"]
assert bdet["vlan10"].active_gateway == ""       # -> N/A in CSV
assert bdet["1/1/1"].access_vlan == 20
print("broken-firmware regression OK (full details survive, AG degrades)")

# AG still collected where the attribute IS supported
class AgFw(_ACR):
    def __init__(self): self.host = "sim-ag"
    def get(self, path, params=None):
        attrs = (params or {}).get("attributes", "")
        if path == "/system/interfaces/*" and "vsx_virtual_ip4" in attrs:
            return {"vlan10": {"vsx_virtual_ip4": ["10.10.0.254/24"]}}
        if path == "/system/interfaces/*":
            return {"vlan10": {"ip4_address": "10.10.0.1/24",
                               "vlan_mode": None, "vlan_tag": None,
                               "vlan_trunks": None, "vrf": None}}
        raise AssertionError(path)

adet = AgFw().interface_details()
assert adet["vlan10"].active_gateway == "10.10.0.254"
print("active-gateway collection OK where supported")
