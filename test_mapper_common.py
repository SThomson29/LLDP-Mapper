"""Shared fixtures: 4-switch topology with VSX-style LAG ISL, LAG uplinks,
a CORP-VRF SVI spanning three switches, a /31 routed link, and loopbacks."""
from lldp_mapper import AosCxRest, Device, PollResult, PortInfo, VsxInfo

MAC = {
    "core-01": "aa:bb:cc:00:00:01",
    "core-02": "aa:bb:cc:00:00:02",
    "acc-01":  "aa:bb:cc:00:01:01",
    "acc-02":  "aa:bb:cc:00:01:02",
}


def _nbr(chassis, port, name=""):
    return AosCxRest._parse_neighbor_map({
        chassis + "," + port: {"neighbor_info": {"chassis_name": name,
                                                 "chassis_description": "",
                                                 "mgmt_ip_list": ""}}})


def _sw(name, ip):
    return Device(key=MAC[name], hostname=name, mgmt_ip=ip,
                  platform="6300M", version="FL.10.13", is_switch=True)


def _port(name, **kw):
    return PortInfo(name=name, **kw)


TRUNK = dict(vlan_mode="native-untagged", native_vlan=1,
             trunk_vlans=[10, 11, 12, 20])


def make_polled():
    """Return (polled, details_by_dev) matching poll_device output shape."""
    core01_det = {
        "lag256": _port("lag256", lag_members=["1/1/49", "1/1/50"], **TRUNK),
        "lag1": _port("lag1", lag_members=["1/1/1"], **TRUNK),
        "lag2": _port("lag2", lag_members=["1/1/2"], **TRUNK),
        "vlan10": _port("vlan10", ip4=["10.1.10.2/24"], vrf="CORP"),
        "loopback0": _port("loopback0", ip4=["192.168.0.1/32"]),
        "1/1/48": _port("1/1/48", ip4=["192.168.255.0/31"]),
    }
    core02_det = {
        "lag256": _port("lag256", lag_members=["1/1/49", "1/1/50"], **TRUNK),
        "lag1": _port("lag1", lag_members=["1/1/1"], **TRUNK),
        "vlan10": _port("vlan10", ip4=["10.1.10.3/24"], vrf="CORP"),
        "loopback0": _port("loopback0", ip4=["192.168.0.2/32"]),
    }
    acc01_det = {
        "lag1": _port("lag1", lag_members=["1/1/51", "1/1/52"], **TRUNK),
        "vlan10": _port("vlan10", ip4=["10.1.10.4/24"], vrf="CORP"),
    }
    acc02_det = {
        "lag1": _port("lag1", lag_members=["1/1/51"], **TRUNK),
        "1/1/48": _port("1/1/48", ip4=["192.168.255.1/31"]),
    }

    polled = [
        PollResult(device=_sw("core-01", "10.0.0.1"), lldp={
            # dual ISL cables — must collapse to one lag256 L2 link
            "1/1/49": _nbr(MAC["core-02"], "1/1/49", "core-02"),
            "1/1/50": _nbr(MAC["core-02"], "1/1/50", "core-02"),
            "1/1/1": _nbr(MAC["acc-01"], "1/1/51", "acc-01"),
            "1/1/2": _nbr(MAC["acc-02"], "1/1/51", "acc-02"),
        }, details=core01_det,
            vsx=VsxInfo(role="primary", vsx_mac="02:01:00:00:01:00",
                        keepalive_peer="10.0.0.2")),
        PollResult(device=_sw("core-02", "10.0.0.2"), lldp={
            "1/1/49": _nbr(MAC["core-01"], "1/1/49", "core-01"),
            "1/1/50": _nbr(MAC["core-01"], "1/1/50", "core-01"),
            "1/1/1": _nbr(MAC["acc-01"], "1/1/52", "acc-01"),
        }, details=core02_det,
            vsx=VsxInfo(role="secondary", vsx_mac="02:01:00:00:01:00",
                        keepalive_peer="10.0.0.1")),
        PollResult(device=_sw("acc-01", "10.0.0.11"), lldp={
            "1/1/51": _nbr(MAC["core-01"], "1/1/1", "core-01"),
            "1/1/52": _nbr(MAC["core-02"], "1/1/1", "core-02"),
        }, details=acc01_det),
        PollResult(device=_sw("acc-02", "10.0.0.12"), lldp={
            "1/1/51": _nbr(MAC["core-01"], "1/1/2", "core-01"),
        }, details=acc02_det),
    ]
    details_by_dev = {
        MAC["core-01"]: core01_det,
        MAC["core-02"]: core02_det,
        MAC["acc-01"]: acc01_det,
        MAC["acc-02"]: acc02_det,
    }
    return polled, details_by_dev
