#!/usr/bin/env python3
"""Tests for VSX pairing, OSPF/BGP routing layer, and diff mode."""
import json
import xml.etree.ElementTree as ET

from lldp_mapper import (
    AosCxRest, Device, Edge, PollResult, Topology, VsxInfo,
    build_l2_edges, build_l3_segments, build_routing_adjs, build_topology,
    detect_vsx_pairs, diff_topologies, load_topology_json, to_diff_drawio,
    to_drawio_xml, to_json,
)
from test_mapper_common import MAC, make_polled

polled, details_by_dev = make_polled()

# --- attach routing data to fixtures -----------------------------------------
core01, core02, acc01, acc02 = polled
# OSPF over the /31 between core-01 (192.168.255.0) and acc-02 (.1)
core01.ospf = [{"vrf": "default", "area": "0.0.0.0", "ifname": "1/1/48",
                "router_id": "192.168.0.12", "if_addr": "192.168.255.1",
                "state": "full"}]
acc02.ospf = [{"vrf": "default", "area": "0.0.0.0", "ifname": "1/1/48",
               "router_id": "192.168.0.1", "if_addr": "192.168.255.0",
               "state": "full"}]
# iBGP between the cores (loopbacks), eBGP from core-01 to an external WAN peer
core01.bgp = [
    {"vrf": "default", "local_as": "65001", "peer_ip": "192.168.0.2",
     "remote_as": "65001", "state": "Established"},
    {"vrf": "default", "local_as": "65001", "peer_ip": "10.99.99.1",
     "remote_as": "64512", "state": "Established"},
]
core02.bgp = [{"vrf": "default", "local_as": "65001",
               "peer_ip": "192.168.0.1", "remote_as": "65001",
               "state": "Established"}]

topo = build_topology(polled, include_endpoints=False)

# --- VSX pair detection -------------------------------------------------------
pairs = detect_vsx_pairs(polled)
assert pairs == [tuple(sorted([MAC["core-01"], MAC["core-02"]]))], pairs
assert topo.devices[MAC["core-01"]].vsx_role == "primary"
assert topo.devices[MAC["core-02"]].vsx_role == "secondary"
assert "VSX primary" in topo.devices[MAC["core-01"]].label
print("VSX pairing OK (matched by shared system MAC, roles annotated)")

# Keepalive fallback: strip the MACs, keep peer IPs
for pr in (core01, core02):
    pr.vsx.vsx_mac = ""
pairs_fb = detect_vsx_pairs(polled)
assert pairs_fb == pairs, pairs_fb
core01.vsx.vsx_mac = core02.vsx.vsx_mac = "02:01:00:00:01:00"
print("VSX keepalive-IP fallback OK")

# --- routing adjacencies -------------------------------------------------------
adjs = build_routing_adjs(polled)
by_proto = {}
for a in adjs:
    by_proto.setdefault(a.protocol, []).append(a)
# OSPF: one adjacency (reported from both sides, deduped), matched by if_addr
assert len(by_proto["ospf"]) == 1
o = by_proto["ospf"][0]
assert {o.a_key, o.b_key} == {MAC["core-01"], MAC["acc-02"]}
assert o.detail == "area 0.0.0.0" and o.state == "FULL"
# BGP: iBGP core pair (deduped, matched via loopback IPs) + one external eBGP
assert len(by_proto["bgp"]) == 2
ibgp = [a for a in by_proto["bgp"] if a.b_key]
ebgp = [a for a in by_proto["bgp"] if a.b_external]
assert len(ibgp) == 1 and {ibgp[0].a_key, ibgp[0].b_key} == {
    MAC["core-01"], MAC["core-02"]}
assert "iBGP AS 65001" in ibgp[0].detail
assert len(ebgp) == 1 and ebgp[0].b_external == "10.99.99.1"
assert "eBGP" in ebgp[0].detail and "64512" in ebgp[0].detail
print(f"routing adjacency OK (1 OSPF, 1 iBGP, 1 external eBGP from "
      f"{sum(len(pr.ospf) + len(pr.bgp) for pr in polled)} raw records)")

# --- four-layer XML with VSX boxes --------------------------------------------
l2 = build_l2_edges(topo, details_by_dev)
l3 = build_l3_segments(details_by_dev)
xml = to_drawio_xml(topo, l2, l3, adjs, pairs, layered=True)
root = ET.fromstring(xml)
cells = root.findall(".//mxCell")
layers = {c.get("id") for c in cells if c.get("parent") == "0"
          and c.get("id") != "0"}
assert layers == {"lyr_phys", "lyr_l2", "lyr_l3", "lyr_rtg"}, layers

def in_layer(lid):
    return [c for c in cells if c.get("parent") == lid]

# VSX boxes: one on physical, one on L2 (cores appear in L2 links)
for lid in ("lyr_phys", "lyr_l2"):
    boxes = [c for c in in_layer(lid) if c.get("value") == "VSX"]
    assert len(boxes) == 1, (lid, len(boxes))
# Routing layer: 3 switch nodes + 1 external + 3 edges
rtg = in_layer("lyr_rtg")
rtg_nodes = [c for c in rtg if c.get("vertex")]
rtg_edges = [c for c in rtg if c.get("edge")]
assert len(rtg_nodes) == 4, len(rtg_nodes)   # core-01, core-02, acc-02, ext
assert len(rtg_edges) == 3, len(rtg_edges)
assert any("external peer" in (c.get("value") or "") for c in rtg_nodes)
styles = " ".join(c.get("style", "") for c in rtg_edges)
assert "#d79b00" in styles and "#9673a6" in styles  # OSPF orange, BGP purple
# VSX pair placed adjacently: their x/y distance smaller than circle radius
geo = {}
for c in in_layer("lyr_phys"):
    if c.get("vertex") and c.get("value", "").startswith("core-"):
        g = c.find("mxGeometry")
        geo[c.get("value").split("\n")[0]] = (float(g.get("x")),
                                              float(g.get("y")))
dx = abs(geo["core-01"][0] - geo["core-02"][0])
dy = abs(geo["core-01"][1] - geo["core-02"][1])
assert (dx ** 2 + dy ** 2) ** 0.5 < 400, (dx, dy)
print("4-layer XML OK (VSX boxes, routing layer, external peer, pair adjacency)")

# --- JSON round trip + diff -----------------------------------------------------
old_json = to_json(topo, adjs, pairs)
old = load_topology_json("/dev/stdin".replace("/dev/stdin", "old.json")) if False else None
with open("old.json", "w") as f:
    f.write(old_json)

# Simulate change: acc-02 replaced by acc-03, plus a new uplink to core-02
new_topo = Topology()
for key, dev in topo.devices.items():
    if key == MAC["acc-02"]:
        continue
    new_topo.upsert_device(Device(**{k: getattr(dev, k)
                                     for k in Device.__dataclass_fields__}))
acc03 = Device(key="aa:bb:cc:00:01:03", hostname="acc-03",
               mgmt_ip="10.0.0.13", platform="6300M", is_switch=True)
new_topo.upsert_device(acc03)
for e in topo.edges.values():
    if MAC["acc-02"] in (e.a_key, e.b_key):
        continue
    new_topo.add_edge(Edge(**vars(e)))
new_topo.add_edge(Edge(a_key=MAC["core-01"], a_port="1/1/2",
                       b_key=acc03.key, b_port="1/1/51"))
new_topo.add_edge(Edge(a_key=MAC["core-02"], a_port="1/1/2",
                       b_key=acc03.key, b_port="1/1/52"))
with open("new.json", "w") as f:
    f.write(to_json(new_topo))

old = load_topology_json("old.json")
new = load_topology_json("new.json")
assert len(old.devices) == 4 and old.devices[MAC["core-01"]].vsx_role == "primary"
diff = diff_topologies(old, new)
assert diff.added_devices == [acc03.key]
assert diff.removed_devices == [MAC["acc-02"]]
assert len(diff.added_links) == 2
assert len(diff.removed_links) == 1      # core-01 <-> acc-02
assert len(diff.unchanged_links) == 4    # 2x ISL + 2x acc-01 uplinks
print("diff OK (+1/-1 devices, +2/-1 links, JSON round-trips vsx_role)")

# Diff diagram: red/green styling present, all edges valid
dxml = to_diff_drawio(old, new, diff)
droot = ET.fromstring(dxml)
dcells = droot.findall(".//mxCell")
dnodes = {c.get("id") for c in dcells if c.get("vertex")}
for e in (c for c in dcells if c.get("edge")):
    assert e.get("source") in dnodes and e.get("target") in dnodes
node_styles = " ".join(c.get("style", "") for c in dcells if c.get("vertex"))
assert "#82b366" in node_styles and "#b85450" in node_styles
assert len([c for c in dcells if c.get("edge")]) == 7
print("diff diagram OK (added green / removed red, edges valid)")

with open("sample_full.drawio", "w") as f:
    f.write(xml)
with open("sample_diff.drawio", "w") as f:
    f.write(to_diff_drawio(old, new, diff))
print("samples written")

# --- v10.16 schema updates -----------------------------------------------------
# Version negotiation: picks switch-declared latest, else highest advertised
assert AosCxRest.pick_version({
    "latest": {"version": "v10.16", "prefix": "/rest/v10.16"},
    "v10.04": {}, "v10.16": {}}) == "v10.16"
assert AosCxRest.pick_version(
    {"v10.04": {}, "v10.08": {}, "v10.13": {}}) == "v10.13"
assert AosCxRest.pick_version({}) == "v10.04"
assert AosCxRest.pick_version({"garbage": {}, "v10.10": {}}) == "v10.10"
print("API version negotiation OK (latest preferred, sane fallbacks)")

# VSX schema: device_role is the real attribute name (10.04-10.16);
# 'role' accepted as defensive fallback; absence of both -> not VSX
class _FakeVsx(AosCxRest):
    def __init__(self, payload):  # bypass network setup entirely
        self._payload = payload
    def get(self, path, params=None):
        return self._payload

v = _FakeVsx({"device_role": "primary", "system_mac": "02:01:00:00:01:00",
              "keepalive_peer_ip": "10.0.0.2"}).vsx_info()
assert v and v.role == "primary" and v.keepalive_peer == "10.0.0.2"
v2 = _FakeVsx({"role": "secondary"}).vsx_info()   # legacy fallback
assert v2 and v2.role == "secondary"
assert _FakeVsx({"system_mac": "02:01:00:00:01:00"}).vsx_info() is None
print("VSX device_role schema OK (primary attr, legacy fallback, non-VSX None)")

# a non-FULL neighbour inside an OSPF hub stays visible as its own edge
from lldp_mapper import RoutingAdj as _RA, Topology as _Tp, Device as _Dv
from lldp_mapper import _XmlBuilder, _render_routing
ht = _Tp()
for k in "abc":
    ht.upsert_device(_Dv(key=k, hostname=f"sw-{k}", is_switch=True))
hpos = {"a": (0, 0), "b": (300, 0), "c": (150, 300)}
hadjs = [_RA("ospf", "default", "a", "b", detail="area 0.0.0.0", state="FULL"),
         _RA("ospf", "default", "b", "c", detail="area 0.0.0.0", state="FULL"),
         _RA("ospf", "default", "a", "c", detail="area 0.0.0.0",
             state="EXSTART")]
hxb = _XmlBuilder(); _render_routing(hxb, "1", ht, hpos, hadjs)
hx = "\n".join(hxb.cells)
assert hx.count("EXSTART") == 1 and "FULL" not in hx, hx
print("routing hub OK (unhealthy adjacency drawn explicitly)")

# device-supplied markup is neutralised in html=1 labels
exb = _XmlBuilder(); exb.node("1", "<b>ap</b> & co\nline2", "html=1;", 0, 0)
ev = ET.fromstring(exb.cells[0]).get("value")
assert ev == "&lt;b&gt;ap&lt;/b&gt; &amp; co\nline2", ev
print("label escaping OK")
