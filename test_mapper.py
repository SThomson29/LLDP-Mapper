#!/usr/bin/env python3
"""Offline tests for lldp_mapper — no switches required."""
import xml.etree.ElementTree as ET

from lldp_mapper import (
    AosCxRest, Device, PollResult, build_topology, normalise_mac,
    to_drawio_xml,
)

def nbr(chassis, port, name="", descr="", mgmt=""):
    return {chassis + "," + port: {
        "neighbor_info": {
            "chassis_name": name,
            "chassis_description": descr,
            "mgmt_ip_list": mgmt,
        },
    }}

# --- normalise_mac ---------------------------------------------------------
assert normalise_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
assert normalise_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
assert normalise_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"
assert normalise_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
print("normalise_mac OK")

# --- neighbour map parsing -------------------------------------------------
raw = {}
raw.update(nbr("AA:BB:CC:00:00:02", "1/1/49", name="core-02"))
raw.update(nbr("11:22:33:44:55:66", "GigabitEthernet0", name="ap-315",
               descr="ArubaOS AP-315"))
parsed = AosCxRest._parse_neighbor_map(raw)
assert len(parsed) == 2
assert {p["port_id"] for p in parsed} == {"1/1/49", "GigabitEthernet0"}
print("neighbour parsing OK")

# --- wildcard parsing (URL-encoded interface keys) --------------------------
wild = {"1%2F1%2F49": nbr("AA:BB:CC:00:00:02", "1/1/49", name="core-02")}
w = AosCxRest._parse_wildcard(wild)
assert list(w.keys()) == ["1/1/49"], w.keys()
print("wildcard parsing OK")

# --- topology build: 4 switches + endpoints, links seen from both sides ----
MAC = {
    "core-01": "aa:bb:cc:00:00:01",
    "core-02": "aa:bb:cc:00:00:02",
    "acc-01":  "aa:bb:cc:00:01:01",
    "acc-02":  "aa:bb:cc:00:01:02",
    "ap-315":  "11:22:33:44:55:66",
    "phone":   "de:ad:be:ef:00:01",
}

def sw(name, ip):
    return Device(key=MAC[name], hostname=name, mgmt_ip=ip,
                  platform="6300M", version="FL.10.13", is_switch=True)

polled = [
    PollResult(device=sw("core-01", "10.0.0.1"), lldp={
        "1/1/49": AosCxRest._parse_neighbor_map(
            nbr(MAC["core-02"].upper(), "1/1/49", name="core-02")),
        "1/1/1": AosCxRest._parse_neighbor_map(
            nbr(MAC["acc-01"], "1/1/51", name="acc-01")),
        "1/1/2": AosCxRest._parse_neighbor_map(
            nbr(MAC["acc-02"], "1/1/51", name="acc-02")),
    }),
    PollResult(device=sw("core-02", "10.0.0.2"), lldp={
        # same ISL link seen from the other side — must dedupe
        "1/1/49": AosCxRest._parse_neighbor_map(
            nbr(MAC["core-01"], "1/1/49", name="core-01")),
        "1/1/1": AosCxRest._parse_neighbor_map(
            nbr(MAC["acc-01"], "1/1/52", name="acc-01")),
    }),
    PollResult(device=sw("acc-01", "10.0.0.11"), lldp={
        "1/1/51": AosCxRest._parse_neighbor_map(
            nbr(MAC["core-01"], "1/1/1", name="core-01")),
        "1/1/52": AosCxRest._parse_neighbor_map(
            nbr(MAC["core-02"], "1/1/1", name="core-02")),
        "1/1/10": AosCxRest._parse_neighbor_map(
            nbr(MAC["ap-315"], "GigabitEthernet0", name="ap-315",
                descr="ArubaOS AP-315", mgmt="10.0.5.10")),
        "1/1/11": AosCxRest._parse_neighbor_map(
            nbr(MAC["phone"], "port1", name="SEP-phone")),
    }),
    PollResult(device=sw("acc-02", "10.0.0.12"), lldp={
        "1/1/51": AosCxRest._parse_neighbor_map(
            nbr(MAC["core-01"], "1/1/2", name="core-01")),
    }),
]

# Switch-only view: endpoints excluded
topo = build_topology(polled, include_endpoints=False)
assert len(topo.devices) == 4, topo.devices.keys()
# links: core01-core02, core01-acc01, core02-acc01, core01-acc02 = 4 unique
assert len(topo.edges) == 4, [e for e in topo.edges]
print(f"switch-only topology OK ({len(topo.devices)} devices, "
      f"{len(topo.edges)} links)")

# With endpoints
topo2 = build_topology(polled, include_endpoints=True)
assert len(topo2.devices) == 6
assert len(topo2.edges) == 6
ap = topo2.devices[MAC["ap-315"]]
assert not ap.is_switch and ap.hostname == "ap-315" and ap.mgmt_ip == "10.0.5.10"
print(f"endpoint topology OK ({len(topo2.devices)} devices, "
      f"{len(topo2.edges)} links)")

# Case-insensitive chassis MAC dedup: core-02 was reported uppercase by
# core-01's LLDP but exists as a scanned device — must not duplicate.
assert MAC["core-02"] in topo.devices
assert "AA:BB:CC:00:00:02".lower() == MAC["core-02"]
print("MAC dedup OK")

# --- draw.io XML validity ---------------------------------------------------
xml = to_drawio_xml(topo2)
root = ET.fromstring(xml)
cells = root.findall(".//mxCell")
vertices = [c for c in cells if c.get("vertex") == "1"
            and c.get("connectable") != "0"]  # exclude edge-end labels
edges = [c for c in cells if c.get("edge") == "1"]
assert len(vertices) == 6, len(vertices)
assert len(edges) == 6, len(edges)
# every edge must reference valid vertex ids
vids = {c.get("id") for c in vertices}
for e in edges:
    assert e.get("source") in vids and e.get("target") in vids
# port labels present at edge ends (child cells parented to edges)
eids = {e.get("id") for e in edges}
end_labels = [c for c in cells if c.get("connectable") == "0"
              and c.get("parent") in eids]
assert any("1/1/49" in (c.get("value") or "") for c in end_labels)
# each end label anchors to a real edge and sits at +/-0.75
for c in end_labels:
    g = c.find("mxGeometry")
    assert float(g.get("x")) in (-0.75, 0.75)
print("draw.io XML OK (parsed, all edges reference valid nodes)")

with open("sample_topology.drawio", "w") as f:
    f.write(xml)
print("sample written")
