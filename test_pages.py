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

# --- single-stack scenario: endpoint links carry VLANs on the L2 page --------
from lldp_mapper import (AosCxRest, Device, PollResult, PortInfo,
                         build_l2_edges as _bl2)

def _n(chassis, port, name):
    return AosCxRest._parse_neighbor_map({
        chassis + "," + port: {"neighbor_info": {
            "chassis_name": name, "chassis_description": "",
            "mgmt_ip_list": ""}}})

stack = Device(key="aa:bb:cc:99:00:01", hostname="stack-01",
               mgmt_ip="10.9.0.1", platform="6300M", is_switch=True)
stack_det = {
    "1/1/10": PortInfo(name="1/1/10", vlan_mode="access", access_vlan=20),
    "1/1/11": PortInfo(name="1/1/11", vlan_mode="native-untagged",
                       native_vlan=1, trunk_vlans=[10, 20, 30]),
}
sp = [PollResult(device=stack, lldp={
    "1/1/10": _n("11:22:33:00:00:01", "eth0", "ap-1"),
    "1/1/11": _n("11:22:33:00:00:02", "ge0", "server-1"),
}, details=stack_det)]
stopo = build_topology(sp, include_endpoints=True)
sdet = {stack.key: stack_det}
# default: no switch-to-switch links -> no L2 edges (old behaviour)
assert _bl2(stopo, sdet) == []
# with endpoints: both links present, VLANs from the switch side
l2e = _bl2(stopo, sdet, include_endpoints=True)
assert len(l2e) == 2
labels = {e.vlan_label for e in l2e}
assert "access 20" in labels
assert any("trunk 10,20,30" in l and "native 1" in l for l in labels)
# and the L2 page now renders for a single stack
sxml = to_drawio_xml(stopo, l2e)
sroot = ET.fromstring(sxml)
assert [d.get("name") for d in sroot.findall("diagram")] == [
    "Physical", "Layer 2"]
l2page = sroot.findall("diagram")[1]
styles = [c.get("style", "") for c in l2page.findall(".//mxCell")
          if c.get("vertex") == "1" and c.get("connectable") != "0"]
assert any("dashed=1" in s and "#999999" in s for s in styles)  # endpoint style
print("single-stack L2 endpoints OK (VLAN labels, L2 page generated)")

# --- single-stack L3: --all-subnets renders SVIs/routed ports as leaves ------
from lldp_mapper import build_l3_segments as _bl3
stack_det["vlan20"] = PortInfo(name="vlan20", ip4=["10.20.0.1/24"])
stack_det["vlan30"] = PortInfo(name="vlan30", ip4=["10.30.0.1/24"],
                               vrf="CORP")
stack_det["1/1/48"] = PortInfo(name="1/1/48", ip4=["192.168.255.0/31"])
stack_det["loopback0"] = PortInfo(name="loopback0", ip4=["192.168.0.9/32"])
# default: single stack -> no shared segments -> no L3 page
assert _bl3(sdet) == []
# all-subnets: three leaf segments, loopback excluded
segs = _bl3(sdet, include_single=True)
assert len(segs) == 3, [s.network for s in segs]
nets = {s.network for s in segs}
assert nets == {"10.20.0.0/24", "10.30.0.0/24", "192.168.255.0/31"}
assert any(s.vrf == "CORP" for s in segs)
sxml3 = to_drawio_xml(stopo, l2e, segs)
sroot3 = ET.fromstring(sxml3)
assert [d.get("name") for d in sroot3.findall("diagram")] == [
    "Physical", "Layer 2", "Layer 3"]
l3page = sroot3.findall("diagram")[2]
l3cells = l3page.findall(".//mxCell")
leaves = [c for c in l3cells if "ellipse" in (c.get("style") or "")]
assert len(leaves) == 3
spokes = [c for c in l3cells if c.get("edge")]
assert len(spokes) == 3
# leaf spoke end label carries the SVI/interface detail
kids = [c for c in l3cells if c.get("connectable") == "0"]
assert any("vlan 20" in (c.get("value") or "") for c in kids)
assert any("1/1/48" in (c.get("value") or "") for c in kids)
print("single-stack L3 OK (leaf subnets, VRF, loopback excluded, L3 page)")

# --- IPAM CSV: flat addressing inventory -------------------------------------
import csv as _csv
import os as _os
from lldp_mapper import _ipam_rows, write_ipam_csv

rows = _ipam_rows(stack_det)
assert ("vlan20", "20", "10.20.0.1/24", "default") in rows
assert ("vlan30", "30", "10.30.0.1/24", "CORP") in rows
assert ("1/1/48", "", "192.168.255.0/31", "default") in rows
assert ("loopback0", "", "192.168.0.9/32", "default") in rows
assert rows[0][0] == "vlan20" and rows[1][0] == "vlan30"
print("IPAM rows OK (SVIs, routed port, loopback, VRF, sorted)")

n = write_ipam_csv("ipam_test.csv", stopo, {stack.key: stack_det})
with open("ipam_test.csv") as f:
    recs = list(_csv.DictReader(f))
assert n == len(recs) == len(rows)
r30 = next(r for r in recs if r["interface"] == "vlan30")
assert r30 == {"hostname": "stack-01", "mgmt_ip": "10.9.0.1",
               "interface": "vlan30", "vlan": "30", "ip": "10.30.0.1",
               "prefix": "24", "network": "10.30.0.0/24", "vrf": "CORP"}
# network column answers "who is on this subnet"
assert [r["interface"] for r in recs
        if r["network"] == "192.168.255.0/31"] == ["1/1/48"]
_os.remove("ipam_test.csv")
print("IPAM CSV OK (flat rows, split ip/prefix/network, filterable)")

# no IPAM tab in the drawing any more
ipam_xml = to_drawio_xml(stopo, l2e, segs)
assert "IPAM" not in [d.get("name")
                      for d in ET.fromstring(ipam_xml).findall("diagram")]
print("IPAM tabs removed from drawings")
