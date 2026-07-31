#!/usr/bin/env python3
"""Tests for the default one-page-per-view output."""
import xml.etree.ElementTree as ET

from lldp_mapper import (
    build_l2_edges, build_l3_segments, build_routing_adjs, build_topology,
    detect_vsx_pairs, to_drawio_xml,
)
from test_mapper_common import MAC, make_polled

polled, details = make_polled()
# attach minimal routing data so the routing page is generated
polled[0].ospf = [{"vrf": "default", "area": "0.0.0.0", "ifname": "1/1/48",
                   "router_id": "192.168.0.12", "if_addr": "192.168.255.1",
                   "state": "full"}]
polled[0].bgp = [{"vrf": "default", "local_as": "65001",
                  "peer_ip": "10.99.99.1", "remote_as": "64512",
                  "state": "Established"}]
topo = build_topology(polled, include_endpoints=False)
l2 = build_l2_edges(topo, details)
l3 = build_l3_segments(details)
adjs = build_routing_adjs(polled)
pairs = detect_vsx_pairs(polled)

xml = to_drawio_xml(topo, l2, l3, adjs, pairs)   # pages is the default
root = ET.fromstring(xml)
diagrams = root.findall("diagram")
assert [d.get("name") for d in diagrams] == [
    "Physical", "Layer 2", "Layer 3", "Routing"], [
    d.get("name") for d in diagrams]
print(f"pages OK ({len(diagrams)} tabs)")

def cells(d):
    return d.findall(".//mxCell")

# Every page stands alone: base layer, valid edge refs, no waypoints
coords = {}   # hostname -> (x, y) per page for cross-page consistency
for d in diagrams:
    cs = cells(d)
    ids = {c.get("id") for c in cs}
    assert "0" in ids and "1" in ids
    nodes = [c for c in cs if c.get("vertex") == "1"
             and c.get("connectable") != "0"]
    vids = {c.get("id") for c in nodes}
    for e in (c for c in cs if c.get("edge")):
        assert e.get("source") in vids and e.get("target") in vids, d.get("name")
        assert e.find("mxGeometry/Array/mxPoint") is None  # no bows on pages
    for c in nodes:
        val = (c.get("value") or "").split("\n")[0]
        if val.startswith(("core-", "acc-")):
            g = c.find("mxGeometry")
            coords.setdefault(val, set()).add((g.get("x"), g.get("y")))
# Same device sits at identical coordinates on every page it appears on
for host, seen in coords.items():
    assert len(seen) == 1, (host, seen)
print("per-page validity OK (standalone pages, no bows, consistent coords)")

# Content spot checks per page
phys, l2p, l3p, rtg = diagrams
assert len([c for c in cells(phys) if c.get("edge")]) == 5
assert any(c.get("value") == "VSX" for c in cells(phys))
assert len([c for c in cells(l2p) if c.get("edge")]) == 4
assert any("ellipse" in (c.get("style") or "") for c in cells(l3p))
assert any("external peer" in (c.get("value") or "") for c in cells(rtg))
print("page content OK (phys cables, L2 aggregation, L3 hub, routing external)")

# physical-only still produces a single-page file
solo = ET.fromstring(to_drawio_xml(topo))
assert [d.get("name") for d in solo.findall("diagram")] == ["Physical"]
print("physical-only single page OK")
