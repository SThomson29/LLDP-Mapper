#!/usr/bin/env python3
"""Tests for L2/L3 layer building and layered draw.io output."""
import xml.etree.ElementTree as ET

from lldp_mapper import (
    AosCxRest, Device, PortInfo, build_l2_edges, build_l3_segments,
    build_topology, compress_vlans, to_drawio_xml, _id_from_uri,
)
from test_mapper_common import MAC, make_polled  # shared fixtures

# --- helpers ---------------------------------------------------------------
assert compress_vlans([10, 11, 12, 20, 30, 31]) == "10-12,20,30-31"
assert compress_vlans([5]) == "5"
assert compress_vlans([]) == ""
assert _id_from_uri("/rest/v10.04/system/vlans/10", int) == 10
assert _id_from_uri("/rest/v10.04/system/vrfs/CORP") == "CORP"
print("helpers OK")

# --- REST port parsing -------------------------------------------------------
raw_trunk = {
    "vlan_mode": "native-untagged",
    "vlan_tag": {"1": "/rest/v10.04/system/vlans/1"},
    "vlan_trunks": {"10": "u", "11": "u", "12": "u", "20": "u"},
    "ip4_address": None,
    "vrf": {"default": "/rest/v10.04/system/vrfs/default"},
}
p = AosCxRest._parse_port("lag256", raw_trunk)
assert p.is_lag and p.native_vlan == 1 and sorted(p.trunk_vlans) == [10, 11, 12, 20]
raw_svi = {
    "vlan_mode": None, "vlan_tag": None, "vlan_trunks": None,
    "ip4_address": "10.1.10.2/24",
    "ip4_address_secondary": ["10.1.99.2/24"],
    "vrf": {"CORP": "/rest/v10.04/system/vrfs/CORP"},
}
s = AosCxRest._parse_port("vlan10", raw_svi)
assert s.is_svi and s.svi_vlan == 10 and s.vrf == "CORP" and len(s.ip4) == 2
raw_lag = {"vlan_mode": "native-untagged", "vlan_tag": None,
           "vlan_trunks": {"10": "u"}, "ip4_address": None,
           "interfaces": {"1/1/49": "u", "1/1/50": "u"}, "vrf": None}
l = AosCxRest._parse_port("lag1", raw_lag)
assert l.lag_members == ["1/1/49", "1/1/50"]
print("port parsing OK")

# --- fixtures: 4-switch topology with LAG ISL and dual uplinks ---------------
polled, details_by_dev = make_polled()
topo = build_topology(polled, include_endpoints=False)

# --- L2: the 2x core ISL cables must collapse into one lag256 link -----------
l2 = build_l2_edges(topo, details_by_dev)
isl = [e for e in l2 if e.a_if == "lag256" and e.b_if == "lag256"]
assert len(isl) == 1, l2
assert isl[0].member_count == 2
assert "trunk 10-12,20" in isl[0].vlan_label and "native 1" in isl[0].vlan_label
# access uplinks (lag on both ends, single member each)
uplinks = [e for e in l2 if "lag" in e.a_if.lower() and e is not isl[0]]
assert len(l2) == 4, [f"{e.a_if}-{e.b_if}" for e in l2]  # ISL + 3 uplinks
print(f"L2 aggregation OK ({len(l2)} L2 links from {len(topo.edges)} physical)")

# --- L3: shared SVI subnet (3 members -> hub) and /31 P2P (direct edge) ------
l3 = build_l3_segments(details_by_dev)
by_net = {s.network: s for s in l3}
assert "10.1.10.0/24" in by_net and len(by_net["10.1.10.0/24"].members) == 3
assert by_net["10.1.10.0/24"].vrf == "CORP"
assert "192.168.255.0/31" in by_net and len(by_net["192.168.255.0/31"].members) == 2
# loopbacks (/32) must not create segments
assert not any(s.network.endswith("/32") for s in l3)
print(f"L3 segments OK ({len(l3)} segments)")

# --- layered XML --------------------------------------------------------------
xml = to_drawio_xml(topo, l2, l3, layered=True)
root = ET.fromstring(xml)
layers = {c.get("id"): c for c in root.findall(".//mxCell")
          if c.get("parent") == "0" and c.get("id") != "0"}
assert set(layers) == {"lyr_phys", "lyr_l2", "lyr_l3"}, layers.keys()
assert layers["lyr_phys"].get("visible") is None      # visible by default
assert layers["lyr_l2"].get("visible") == "0"
assert layers["lyr_l3"].get("visible") == "0"

cells = root.findall(".//mxCell")
def in_layer(layer):
    return [c for c in cells if c.get("parent") == layer]
phys = in_layer("lyr_phys"); l2c = in_layer("lyr_l2"); l3c = in_layer("lyr_l3")
assert len([c for c in phys if c.get("vertex")]) == 4
assert len([c for c in phys if c.get("edge")]) == 5   # incl 2x ISL cables
assert len([c for c in l2c if c.get("edge")]) == 4    # ISL collapsed
# L3: 3-member subnet -> 1 hub + 3 spokes; /31 -> 1 direct edge
hubs = [c for c in l3c if c.get("vertex") and "ellipse" in c.get("style", "")]
assert len(hubs) == 1
assert len([c for c in l3c if c.get("edge")]) == 4
# edges reference ids within their own layer
for layer, cs in (("lyr_phys", phys), ("lyr_l2", l2c), ("lyr_l3", l3c)):
    vids = {c.get("id") for c in cs if c.get("vertex")}
    for e in (c for c in cs if c.get("edge")):
        assert e.get("source") in vids and e.get("target") in vids, layer
print("layered XML OK (3 layers, correct visibility, edges scoped per layer)")

with open("sample_layered.drawio", "w") as f:
    f.write(xml)
print("sample written")

# --- multi-layer overlay: L2/L3 edges bow away from physical -----------------
def edges_of(layer):
    return [c for c in cells if c.get("parent") == layer and c.get("edge")]
def has_waypoint(e):
    return e.find("mxGeometry/Array/mxPoint") is not None
assert not any(has_waypoint(e) for e in edges_of("lyr_phys"))
assert all(has_waypoint(e) for e in edges_of("lyr_l2"))
# L3: p2p edges bow; hub spokes don't need to
l3_wp = [e for e in edges_of("lyr_l3") if has_waypoint(e)]
assert len(l3_wp) >= 1
# L2 and L3 bow to opposite sides of the same link where both exist
assert "curved=1" in edges_of("lyr_l2")[0].get("style", "")
print("layer overlay bowing OK (phys straight, L2/L3 curved with waypoints)")

# trunk with an empty allowed list = all VLANs on AOS-CX
from lldp_mapper import _vlan_label
assert _vlan_label(PortInfo(name="1/1/1", vlan_mode="native-untagged",
                            native_vlan=1)) == "trunk all · native 1"
assert _vlan_label(PortInfo(name="1/1/2", vlan_mode="access",
                            access_vlan=20)) == "access 20"
assert _vlan_label(PortInfo(name="1/1/3")) == ""
print("trunk-all label OK")
