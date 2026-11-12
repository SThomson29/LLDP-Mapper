#!/usr/bin/env python3
"""Shared synthetic fixtures for the offline test suites.

A four-switch estate: a VSX core pair with a two-cable LAG ISL, acc-01
dual-homed to both cores, and acc-02 single-homed to core-01 with a
routed /31 and an OSPF adjacency over it.

Deliberate properties the suites rely on:
  * 5 physical cables, 4 L2 links (the 2x ISL collapses into lag256)
  * exactly 2 shared L3 segments: 10.1.10.0/24 in VRF CORP across three
    switches (renders as a hub), and 192.168.255.0/31 point-to-point
  * loopbacks are /32 so they must never become segments
  * OSPF if_addr / router_id values point at the PEER, so peer matching
    is exercised rather than trivially self-matching
"""
from lldp_mapper import (
    AosCxRest, Device, PollResult, PortInfo, VsxInfo,
)

MAC = {
    "core-01": "aa:bb:cc:00:00:01",
    "core-02": "aa:bb:cc:00:00:02",
    "acc-01":  "aa:bb:cc:00:01:01",
    "acc-02":  "aa:bb:cc:00:01:02",
}

MGMT = {
    "core-01": "10.0.0.1",
    "core-02": "10.0.0.2",
    "acc-01":  "10.0.0.11",
    "acc-02":  "10.0.0.12",
}

VSX_SYSTEM_MAC = "02:01:00:00:01:00"

TRUNK = [10, 11, 12, 20]


def nbr(chassis, port, name="", descr="", mgmt=""):
    """One raw LLDP neighbour map entry, as the REST API returns it."""
    return {chassis + "," + port: {
        "neighbor_info": {
            "chassis_name": name,
            "chassis_description": descr,
            "mgmt_ip_list": mgmt,
        },
    }}


def _sw(name):
    return Device(key=MAC[name], hostname=name, mgmt_ip=MGMT[name],
                  platform="6300M", version="FL.10.13", is_switch=True)


def _trunk_lag(name, members):
    return PortInfo(name=name, vlan_mode="native-untagged", native_vlan=1,
                    trunk_vlans=list(TRUNK), lag_members=list(members))


def make_polled():
    """Return (polled, details_by_dev) for the shared four-switch estate."""
    details = {
        "core-01": {
            # 2x ISL cables in one LAG -> one L2 edge, member_count 2
            "lag256": _trunk_lag("lag256", ["1/1/49", "1/1/50"]),
            "lag1": _trunk_lag("lag1", ["1/1/1"]),      # -> acc-01
            "lag2": _trunk_lag("lag2", ["1/1/2"]),      # -> acc-02
            "vlan10": PortInfo(name="vlan10", ip4=["10.1.10.1/24"],
                               vrf="CORP"),
            "1/1/48": PortInfo(name="1/1/48", ip4=["192.168.255.0/31"]),
            "loopback0": PortInfo(name="loopback0",
                                  ip4=["192.168.0.1/32"]),
        },
        "core-02": {
            "lag256": _trunk_lag("lag256", ["1/1/49", "1/1/50"]),
            "lag1": _trunk_lag("lag1", ["1/1/1"]),      # -> acc-01
            "vlan10": PortInfo(name="vlan10", ip4=["10.1.10.2/24"],
                               vrf="CORP"),
            "loopback0": PortInfo(name="loopback0",
                                  ip4=["192.168.0.2/32"]),
        },
        "acc-01": {
            # MC-LAG to both cores; still two L2 edges, one per peer
            "lag1": _trunk_lag("lag1", ["1/1/51", "1/1/52"]),
            "vlan10": PortInfo(name="vlan10", ip4=["10.1.10.3/24"],
                               vrf="CORP"),
        },
        "acc-02": {
            "lag2": _trunk_lag("lag2", ["1/1/51"]),
            "1/1/48": PortInfo(name="1/1/48", ip4=["192.168.255.1/31"]),
            "loopback0": PortInfo(name="loopback0",
                                  ip4=["192.168.0.12/32"]),
        },
    }

    # local interface -> raw neighbour map, exactly as lldp_neighbors()
    # would return it.
    raw_lldp = {
        "core-01": {
            "1/1/49": nbr(MAC["core-02"].upper(), "1/1/49", name="core-02"),
            "1/1/50": nbr(MAC["core-02"], "1/1/50", name="core-02"),
            "1/1/1": nbr(MAC["acc-01"], "1/1/51", name="acc-01"),
            "1/1/2": nbr(MAC["acc-02"], "1/1/51", name="acc-02"),
        },
        "core-02": {
            # the same two ISL cables from the other side — must dedupe
            "1/1/49": nbr(MAC["core-01"], "1/1/49", name="core-01"),
            "1/1/50": nbr(MAC["core-01"], "1/1/50", name="core-01"),
            "1/1/1": nbr(MAC["acc-01"], "1/1/52", name="acc-01"),
        },
        "acc-01": {
            "1/1/51": nbr(MAC["core-01"], "1/1/1", name="core-01"),
            "1/1/52": nbr(MAC["core-02"], "1/1/1", name="core-02"),
        },
        "acc-02": {
            "1/1/51": nbr(MAC["core-01"], "1/1/2", name="core-01"),
        },
    }

    polled = []
    for name in ("core-01", "core-02", "acc-01", "acc-02"):
        by_if = {ifname: AosCxRest._parse_neighbor_map(raw)
                 for ifname, raw in raw_lldp[name].items()}
        vsx = None
        if name.startswith("core-"):
            peer = "core-02" if name == "core-01" else "core-01"
            vsx = VsxInfo(
                role="primary" if name == "core-01" else "secondary",
                vsx_mac=VSX_SYSTEM_MAC,
                keepalive_peer=MGMT[peer],
            )
        polled.append(PollResult(device=_sw(name), lldp=by_if,
                                 details=details[name], vsx=vsx))

    details_by_dev = {MAC[n]: d for n, d in details.items()}
    return polled, details_by_dev
