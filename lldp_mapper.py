#!/usr/bin/env python3
"""
lldp_mapper.py — AOS-CX LLDP topology mapper.

Scans a subnet for AOS-CX switches (REST API on tcp/443), pulls LLDP
neighbour data via the AOS-CX REST API, builds a deduplicated topology
graph, and emits a draw.io XML diagram.

Usage:
    python3 lldp_mapper.py 10.20.30.0/24 -u admin -o topology.drawio
    python3 lldp_mapper.py 10.20.30.0/24 -u admin --include-endpoints
    python3 lldp_mapper.py 10.20.30.0/24 -u admin --json inventory.json

Credentials: password is taken from the AOSCX_PASSWORD environment
variable if set, otherwise prompted interactively (never on the CLI).

Only stdlib + requests. Designed for AOS-CX 10.04+.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import getpass
import ipaddress
import json
import logging
import math
import os
import re
import socket
import sys
import urllib.parse
from dataclasses import dataclass, field
from xml.sax.saxutils import escape

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("lldp_mapper")

DEFAULT_API_VERSION = "auto"      # negotiate latest via GET /rest
FALLBACK_API_VERSION = "v10.04"   # served by all 10.04+ firmware
HTTPS_PORT = 443
CONNECT_TIMEOUT = 2.0
HTTP_TIMEOUT = 10.0


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

def normalise_mac(raw: str) -> str:
    """Normalise any common MAC representation to aa:bb:cc:dd:ee:ff."""
    hexonly = re.sub(r"[^0-9a-fA-F]", "", raw or "")
    if len(hexonly) != 12:
        return (raw or "").strip().lower()
    return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2)).lower()


def _id_from_uri(uri, cast=str):
    """Extract the trailing id from an AOS-CX REST URI or passthrough value."""
    if uri is None:
        return None
    s = urllib.parse.unquote(str(uri)).rstrip("/")
    tail = s.rsplit("/", 1)[-1]
    try:
        return cast(tail)
    except (TypeError, ValueError):
        return None


def _keys_or_uris(val, cast=str) -> list:
    """AOS-CX returns references as {id: uri} dicts or lists of URIs.

    Dict keys ARE the ids (e.g. "1/1/49" for a LAG member) and must not
    be URI-split; list entries are URIs whose tail is the id.
    """
    if not val:
        return []
    out = []
    if isinstance(val, dict):
        for key in val.keys():
            try:
                out.append(cast(urllib.parse.unquote(str(key))))
            except (TypeError, ValueError):
                continue
    else:
        for item in val:
            parsed = _id_from_uri(item, cast)
            if parsed is not None:
                out.append(parsed)
    return out


@dataclass
class PortInfo:
    name: str
    vlan_mode: str = ""             # access | native-untagged | native-tagged
    access_vlan: int | None = None
    native_vlan: int | None = None
    trunk_vlans: list[int] = field(default_factory=list)
    ip4: list[str] = field(default_factory=list)   # CIDR strings
    vrf: str = "default"
    lag_members: list[str] = field(default_factory=list)  # set on lagN ifs

    @property
    def is_lag(self) -> bool:
        return self.name.lower().startswith("lag")

    @property
    def is_svi(self) -> bool:
        return self.name.lower().startswith("vlan")

    @property
    def svi_vlan(self) -> int | None:
        m = re.match(r"vlan\s*(\d+)$", self.name.lower())
        return int(m.group(1)) if m else None


def compress_vlans(vlans: list[int]) -> str:
    """[10,11,12,20] -> '10-12,20'."""
    if not vlans:
        return ""
    vs = sorted(set(vlans))
    ranges, start, prev = [], vs[0], vs[0]
    for v in vs[1:]:
        if v == prev + 1:
            prev = v
            continue
        ranges.append(f"{start}-{prev}" if prev > start else str(start))
        start = prev = v
    ranges.append(f"{start}-{prev}" if prev > start else str(start))
    return ",".join(ranges)


@dataclass
class Device:
    key: str                      # normalised chassis MAC (or fallback id)
    hostname: str = ""
    mgmt_ip: str = ""
    platform: str = ""
    version: str = ""
    is_switch: bool = False      # True if we logged into it via REST
    sys_descr: str = ""
    vsx_role: str = ""           # "primary" / "secondary" if VSX member

    @property
    def label(self) -> str:
        parts = [self.hostname or self.key]
        if self.mgmt_ip:
            parts.append(self.mgmt_ip)
        if self.platform:
            parts.append(self.platform)
        if self.vsx_role:
            parts.append(f"VSX {self.vsx_role}")
        return "\n".join(parts)


@dataclass
class Edge:
    a_key: str
    a_port: str
    b_key: str
    b_port: str

    def canonical(self) -> tuple:
        ends = sorted([(self.a_key, self.a_port), (self.b_key, self.b_port)])
        return (ends[0], ends[1])


@dataclass
class Topology:
    devices: dict[str, Device] = field(default_factory=dict)
    edges: dict[tuple, Edge] = field(default_factory=dict)

    def upsert_device(self, dev: Device) -> Device:
        existing = self.devices.get(dev.key)
        if existing is None:
            self.devices[dev.key] = dev
            return dev
        # Prefer authoritative (scanned) data over LLDP-learned data.
        for attr in ("hostname", "mgmt_ip", "platform", "version", "sys_descr"):
            if not getattr(existing, attr) and getattr(dev, attr):
                setattr(existing, attr, getattr(dev, attr))
        existing.is_switch = existing.is_switch or dev.is_switch
        return existing

    def add_edge(self, edge: Edge) -> None:
        self.edges.setdefault(edge.canonical(), edge)


@dataclass
class VsxInfo:
    role: str = ""               # primary | secondary
    vsx_mac: str = ""            # configured VSX system MAC (shared by pair)
    keepalive_peer: str = ""


@dataclass
class RoutingAdj:
    protocol: str                # "ospf" | "bgp"
    vrf: str
    a_key: str                   # device key of the reporting side
    b_key: str = ""              # device key if peer matched to inventory
    b_external: str = ""         # peer IP if unmatched (WAN router, fw, ...)
    detail: str = ""             # "area 0.0.0.0" / "AS 65001<->65010"
    state: str = ""

    def canonical(self) -> tuple:
        peer = self.b_key or f"ext:{self.b_external}"
        ends = tuple(sorted([self.a_key, peer]))
        return (self.protocol, self.vrf, ends)

    @property
    def label(self) -> str:
        bits = [self.protocol.upper()]
        if self.vrf != "default":
            bits.append(f"vrf {self.vrf}")
        if self.detail:
            bits.append(self.detail)
        if self.state:
            bits.append(self.state)
        return " · ".join(bits)


@dataclass
class PollResult:
    device: Device
    lldp: dict[str, list[dict]] = field(default_factory=dict)
    details: dict[str, PortInfo] = field(default_factory=dict)
    vsx: VsxInfo | None = None
    ospf: list[dict] = field(default_factory=list)   # raw neighbour records
    bgp: list[dict] = field(default_factory=list)


# --------------------------------------------------------------------------
# AOS-CX REST client
# --------------------------------------------------------------------------

class AosCxRest:
    """Minimal AOS-CX REST session with guaranteed logout.

    AOS-CX limits concurrent REST sessions per switch, so logout on all
    paths matters — use as a context manager.
    """

    def __init__(self, host: str, username: str, password: str,
                 api_version: str = DEFAULT_API_VERSION, verify: bool = False):
        self.host = host
        self.api_version = api_version
        self.base = ""            # set on __enter__ after negotiation
        self.username = username
        self.password = password
        self.verify = verify
        self.session = requests.Session()
        self.session.verify = verify
        self._logged_in = False

    @staticmethod
    def pick_version(rest_index: dict) -> str:
        """Choose a version from the GET /rest response.

        Prefers the switch-declared 'latest' (e.g. v10.16 on 10.16
        firmware, per Aruba's stated best practice); otherwise the
        highest advertised vX.Y key.
        """
        latest = rest_index.get("latest")
        if isinstance(latest, dict) and latest.get("version"):
            return str(latest["version"])
        candidates = []
        for key in rest_index:
            m = re.fullmatch(r"v(\d+)\.(\d+)", str(key))
            if m:
                candidates.append((int(m.group(1)), int(m.group(2)), key))
        if candidates:
            return max(candidates)[2]
        return FALLBACK_API_VERSION

    def _negotiate_version(self) -> str:
        """GET /rest (unauthenticated) and pick the latest version.

        Falls back to v10.04 if the index is unreachable or unparsable —
        that version is published by all 10.04+ firmware and shares the
        newest schema on modern releases.
        """
        try:
            r = self.session.get(f"https://{self.host}/rest",
                                 timeout=HTTP_TIMEOUT)
            r.raise_for_status()
            version = self.pick_version(r.json() or {})
        except (requests.RequestException, ValueError):
            log.debug("%s: /rest version index unavailable, using %s",
                      self.host, FALLBACK_API_VERSION)
            return FALLBACK_API_VERSION
        log.debug("%s: negotiated API version %s", self.host, version)
        return version

    def __enter__(self) -> "AosCxRest":
        version = (self._negotiate_version()
                   if self.api_version == "auto" else self.api_version)
        self.api_version = version
        self.base = f"https://{self.host}/rest/{version}"
        r = self.session.post(
            f"{self.base}/login",
            data={"username": self.username, "password": self.password},
            timeout=HTTP_TIMEOUT,
        )
        r.raise_for_status()
        self._logged_in = True
        return self

    def __exit__(self, *exc) -> None:
        if self._logged_in:
            try:
                self.session.post(f"{self.base}/logout", timeout=HTTP_TIMEOUT)
            except requests.RequestException:
                log.warning("%s: logout failed (session may linger)", self.host)
        self.session.close()

    def get(self, path: str, params: dict | None = None):
        r = self.session.get(f"{self.base}{path}", params=params,
                             timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json()

    # -- high level -------------------------------------------------------

    def system_info(self) -> dict:
        return self.get("/system", params={
            "attributes": "hostname,platform_name,software_version,system_mac",
        })

    def interface_names(self) -> list[str]:
        data = self.get("/system/interfaces")
        # Returned as {"1/1/1": "/rest/.../1%2F1%2F1", ...}
        return list(data.keys())

    def lldp_neighbors(self) -> dict[str, list[dict]]:
        """Return {local_ifname: [neighbor_dict, ...]}.

        Tries the wildcard query first (single call, newer firmware),
        falls back to per-interface iteration on older releases.
        """
        try:
            data = self.get("/system/interfaces/*/lldp_neighbors",
                            params={"depth": 2})
            return self._parse_wildcard(data)
        except requests.HTTPError:
            log.debug("%s: wildcard LLDP query unsupported, iterating",
                      self.host)
        result: dict[str, list[dict]] = {}
        for ifname in self.interface_names():
            enc = urllib.parse.quote(ifname, safe="")
            try:
                data = self.get(f"/system/interfaces/{enc}/lldp_neighbors",
                                params={"depth": 2})
            except requests.HTTPError:
                continue
            neighbors = self._parse_neighbor_map(data)
            if neighbors:
                result[ifname] = neighbors
        return result

    IF_ATTRS = ("vlan_mode,vlan_tag,vlan_trunks,ip4_address,"
                "ip4_address_secondary,interfaces,vrf")

    def vsx_info(self) -> VsxInfo | None:
        """Return VSX config, or None if the switch isn't a VSX member.

        Schema note: the role attribute is `device_role` in the AOS-CX
        VSX table (10.04 through 10.16); `role` is kept as a defensive
        fallback only.
        """
        try:
            data = self.get("/system/vsx", params={"depth": 1})
        except requests.HTTPError:
            return None
        role = (data or {}).get("device_role") or (data or {}).get("role")
        if not data or not role:
            return None
        peer = data.get("keepalive_peer_ip") or data.get("keepalive_peer")
        if isinstance(peer, dict):
            peer = next(iter(peer), "")
        return VsxInfo(
            role=str(role),
            vsx_mac=normalise_mac(str(data.get("system_mac") or "")),
            keepalive_peer=str(peer or "").split("/")[0],
        )

    def vrf_names(self) -> list[str]:
        try:
            return _keys_or_uris(self.get("/system/vrfs")) or ["default"]
        except requests.HTTPError:
            return ["default"]

    def _collection(self, path: str) -> list[str]:
        """GET a collection resource, returning ids; [] on any error."""
        try:
            return _keys_or_uris(self.get(path))
        except requests.HTTPError:
            return []

    def ospf_neighbors(self) -> list[dict]:
        """Walk vrfs -> ospf_routers -> areas -> ospf_interfaces -> neighbors.

        Returns [{vrf, area, ifname, router_id, if_addr, state}]. Every
        level is best-effort: a missing resource just prunes that branch.
        """
        out = []
        for vrf in self.vrf_names():
            base = (f"/system/vrfs/{urllib.parse.quote(str(vrf), safe='')}"
                    f"/ospf_routers")
            for pid in self._collection(base):
                rbase = f"{base}/{urllib.parse.quote(str(pid), safe='')}"
                for area in self._collection(f"{rbase}/areas"):
                    abase = (f"{rbase}/areas/"
                             f"{urllib.parse.quote(str(area), safe='')}"
                             f"/ospf_interfaces")
                    for ifname in self._collection(abase):
                        ienc = urllib.parse.quote(str(ifname), safe="")
                        try:
                            nbrs = self.get(f"{abase}/{ienc}/ospf_neighbors",
                                            params={"depth": 2})
                        except requests.HTTPError:
                            continue
                        for val in (nbrs or {}).values():
                            if not isinstance(val, dict):
                                continue
                            out.append({
                                "vrf": str(vrf),
                                "area": str(area),
                                "ifname": str(ifname),
                                "router_id": str(val.get("nbr_router_id")
                                                 or ""),
                                "if_addr": str(val.get("nbr_if_addr") or ""),
                                "state": str(val.get("nfsm_state")
                                             or val.get("state") or ""),
                            })
        return out

    def bgp_neighbors(self) -> list[dict]:
        """Returns [{vrf, local_as, peer_ip, remote_as, state}]."""
        out = []
        for vrf in self.vrf_names():
            base = (f"/system/vrfs/{urllib.parse.quote(str(vrf), safe='')}"
                    f"/bgp_routers")
            for asn in self._collection(base):
                aenc = urllib.parse.quote(str(asn), safe="")
                try:
                    nbrs = self.get(f"{base}/{aenc}/bgp_neighbors",
                                    params={"depth": 2})
                except requests.HTTPError:
                    continue
                for peer_ip, val in (nbrs or {}).items():
                    if not isinstance(val, dict):
                        continue
                    status = val.get("status") or {}
                    state = (str(status.get("bgp_peer_state") or "")
                             if isinstance(status, dict) else "")
                    out.append({
                        "vrf": str(vrf),
                        "local_as": str(asn),
                        "peer_ip": urllib.parse.unquote(str(peer_ip)),
                        "remote_as": str(val.get("remote_as") or ""),
                        "state": state,
                    })
        return out

    def interface_details(self) -> dict[str, PortInfo]:
        """Return {ifname: PortInfo} for every interface.

        Wildcard first, per-interface fallback, matching lldp_neighbors().
        """
        try:
            data = self.get("/system/interfaces/*",
                            params={"attributes": self.IF_ATTRS, "depth": 2})
            return {urllib.parse.unquote(k): self._parse_port(
                        urllib.parse.unquote(k), v)
                    for k, v in (data or {}).items() if isinstance(v, dict)}
        except requests.HTTPError:
            log.debug("%s: wildcard interface query unsupported, iterating",
                      self.host)
        result: dict[str, PortInfo] = {}
        for ifname in self.interface_names():
            enc = urllib.parse.quote(ifname, safe="")
            try:
                data = self.get(f"/system/interfaces/{enc}",
                                params={"attributes": self.IF_ATTRS,
                                        "depth": 1})
            except requests.HTTPError:
                continue
            result[ifname] = self._parse_port(ifname, data)
        return result

    @staticmethod
    def _parse_port(name: str, data: dict) -> PortInfo:
        p = PortInfo(name=name)
        p.vlan_mode = data.get("vlan_mode") or ""
        tag = _id_from_uri(
            next(iter(data["vlan_tag"]), None)
            if isinstance(data.get("vlan_tag"), dict) else data.get("vlan_tag"),
            int)
        if p.vlan_mode == "access":
            p.access_vlan = tag
        elif p.vlan_mode:
            p.native_vlan = tag
        p.trunk_vlans = _keys_or_uris(data.get("vlan_trunks"), int)
        primary = data.get("ip4_address")
        if primary:
            p.ip4.append(primary)
        for extra in data.get("ip4_address_secondary") or []:
            p.ip4.append(extra)
        p.vrf = _id_from_uri(
            next(iter(data["vrf"]), None)
            if isinstance(data.get("vrf"), dict) else data.get("vrf")
        ) or "default"
        p.lag_members = _keys_or_uris(data.get("interfaces"))
        return p

    @staticmethod
    def _parse_neighbor_map(data: dict) -> list[dict]:
        """Parse a per-interface lldp_neighbors response.

        Keys look like "aa:bb:cc:dd:ee:ff,1/1/28"; values hold the detail.
        """
        out = []
        for key, val in (data or {}).items():
            if not isinstance(val, dict):
                continue
            chassis_id, _, port_id = key.partition(",")
            entry = {"chassis_id": chassis_id, "port_id": port_id}
            entry.update(val)
            out.append(entry)
        return out

    @classmethod
    def _parse_wildcard(cls, data: dict) -> dict[str, list[dict]]:
        """Wildcard responses are keyed by interface name (URL-encoded)."""
        result: dict[str, list[dict]] = {}
        for ifname_enc, nbr_map in (data or {}).items():
            ifname = urllib.parse.unquote(ifname_enc)
            neighbors = cls._parse_neighbor_map(nbr_map)
            if neighbors:
                result[ifname] = neighbors
        return result


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def port_open(ip: str, port: int = HTTPS_PORT,
              timeout: float = CONNECT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_subnet(cidr: str, workers: int = 64) -> list[str]:
    """Return hosts in the subnet with tcp/443 open."""
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    log.info("Scanning %d hosts in %s for tcp/%d ...",
             len(hosts), cidr, HTTPS_PORT)
    alive = []
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(port_open, ip): ip for ip in hosts}
        for fut in cf.as_completed(futures):
            if fut.result():
                alive.append(futures[fut])
    log.info("%d host(s) responding on tcp/%d", len(alive), HTTPS_PORT)
    return sorted(alive, key=ipaddress.ip_address)


def poll_device(ip: str, username: str, password: str, api_version: str,
                verify: bool, want_details: bool = True,
                want_routing: bool = True) -> PollResult | None:
    """Log into one switch and gather everything in a single session."""
    details: dict[str, PortInfo] = {}
    vsx: VsxInfo | None = None
    ospf: list[dict] = []
    bgp: list[dict] = []
    try:
        with AosCxRest(ip, username, password, api_version, verify) as api:
            negotiated = api.api_version
            sysinfo = api.system_info()
            lldp = api.lldp_neighbors()
            if want_details:
                details = api.interface_details()
                vsx = api.vsx_info()
            if want_routing:
                ospf = api.ospf_neighbors()
                bgp = api.bgp_neighbors()
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else "?"
        log.warning("%s: REST error %s — skipping (not AOS-CX, or bad creds)",
                    ip, code)
        return None
    except requests.RequestException as exc:
        log.warning("%s: unreachable via REST (%s)", ip, type(exc).__name__)
        return None

    dev = Device(
        key=normalise_mac(sysinfo.get("system_mac", "")) or ip,
        hostname=sysinfo.get("hostname", ""),
        mgmt_ip=ip,
        platform=sysinfo.get("platform_name", ""),
        version=str(sysinfo.get("software_version", "")),
        is_switch=True,
    )
    n_nbrs = sum(len(v) for v in lldp.values())
    log.info("%s (%s, %s): %d LLDP neighbour(s) on %d interface(s)",
             dev.hostname or ip, ip, negotiated, n_nbrs, len(lldp))
    return PollResult(device=dev, lldp=lldp, details=details,
                      vsx=vsx, ospf=ospf, bgp=bgp)


def neighbor_to_device(nbr: dict) -> Device:
    info = nbr.get("neighbor_info") or {}
    mgmt_ips = info.get("mgmt_ip_list") or ""
    if isinstance(mgmt_ips, list):
        mgmt_ip = mgmt_ips[0] if mgmt_ips else ""
    else:
        mgmt_ip = str(mgmt_ips).split(",")[0].strip()
    return Device(
        key=normalise_mac(nbr.get("chassis_id", "")),
        hostname=info.get("chassis_name", "") or "",
        mgmt_ip=mgmt_ip,
        sys_descr=info.get("chassis_description", "") or "",
    )


def build_topology(polled: list[PollResult],
                   include_endpoints: bool) -> Topology:
    topo = Topology()
    for pr in polled:
        topo.upsert_device(pr.device)

    switch_keys = set(topo.devices.keys())

    for pr in polled:
        dev, lldp = pr.device, pr.lldp
        for local_if, neighbors in lldp.items():
            for nbr in neighbors:
                remote = neighbor_to_device(nbr)
                if not remote.key:
                    continue
                if remote.key not in switch_keys and not include_endpoints:
                    continue
                topo.upsert_device(remote)
                topo.add_edge(Edge(
                    a_key=dev.key, a_port=local_if,
                    b_key=remote.key,
                    b_port=nbr.get("port_id", "") or "",
                ))
    return topo


@dataclass
class L2Edge:
    a_key: str
    a_if: str        # lag name or physical port
    b_key: str
    b_if: str
    vlan_label: str = ""
    member_count: int = 1


def _member_to_lag(details: dict[str, PortInfo]) -> dict[str, str]:
    out = {}
    for p in details.values():
        if p.is_lag:
            for member in p.lag_members:
                out[member] = p.name
    return out


def _vlan_label(p: PortInfo | None) -> str:
    if p is None:
        return ""
    if p.vlan_mode == "access" and p.access_vlan is not None:
        return f"access {p.access_vlan}"
    parts = []
    if p.trunk_vlans:
        parts.append(f"trunk {compress_vlans(p.trunk_vlans)}")
    if p.native_vlan is not None:
        parts.append(f"native {p.native_vlan}")
    return " · ".join(parts)


def build_l2_edges(topo: Topology,
                   details_by_dev: dict[str, dict[str, PortInfo]]
                   ) -> list[L2Edge]:
    """Collapse physical switch-to-switch links into LAG-level L2 links."""
    grouped: dict[tuple, L2Edge] = {}
    for edge in topo.edges.values():
        da = topo.devices.get(edge.a_key)
        db = topo.devices.get(edge.b_key)
        if not (da and db and da.is_switch and db.is_switch):
            continue
        det_a = details_by_dev.get(edge.a_key, {})
        det_b = details_by_dev.get(edge.b_key, {})
        if_a = _member_to_lag(det_a).get(edge.a_port, edge.a_port)
        if_b = _member_to_lag(det_b).get(edge.b_port, edge.b_port)

        ends = sorted([(edge.a_key, if_a), (edge.b_key, if_b)])
        key = (ends[0], ends[1])
        if key in grouped:
            grouped[key].member_count += 1
            continue
        # VLAN config lives on the aggregated interface (LAG or port).
        label = _vlan_label(det_a.get(if_a)) or _vlan_label(det_b.get(if_b))
        grouped[key] = L2Edge(
            a_key=ends[0][0], a_if=ends[0][1],
            b_key=ends[1][0], b_if=ends[1][1],
            vlan_label=label,
        )
    return list(grouped.values())


@dataclass
class L3Segment:
    vrf: str
    network: str                       # e.g. "10.1.10.0/24"
    members: dict[str, str] = field(default_factory=dict)  # dev_key -> detail

    @property
    def label(self) -> str:
        vrf = "" if self.vrf == "default" else f"vrf {self.vrf} · "
        return f"{vrf}{self.network}"


def build_l3_segments(details_by_dev: dict[str, dict[str, PortInfo]]
                      ) -> list[L3Segment]:
    """Group SVI/routed-port IPs into shared (vrf, subnet) segments."""
    segments: dict[tuple, L3Segment] = {}
    for dev_key, details in details_by_dev.items():
        for p in details.values():
            for addr in p.ip4:
                try:
                    iface = ipaddress.ip_interface(addr)
                except ValueError:
                    continue
                if iface.network.prefixlen >= 32:
                    continue  # loopbacks aren't adjacency
                seg_key = (p.vrf, str(iface.network))
                seg = segments.setdefault(
                    seg_key, L3Segment(vrf=p.vrf,
                                       network=str(iface.network)))
                detail = f"{p.name} {iface.ip}"
                if p.is_svi and p.svi_vlan is not None:
                    detail = f"vlan {p.svi_vlan} · {iface.ip}"
                seg.members[dev_key] = detail
    # Only segments connecting 2+ devices are topology-relevant.
    return [s for s in segments.values() if len(s.members) >= 2]


# --------------------------------------------------------------------------
# Routing adjacency (OSPF / BGP)
# --------------------------------------------------------------------------

def build_ip_index(polled: list[PollResult]) -> dict[str, str]:
    """Map every known interface/mgmt IP -> device key."""
    index: dict[str, str] = {}
    for pr in polled:
        if pr.device.mgmt_ip:
            index[pr.device.mgmt_ip] = pr.device.key
        for p in pr.details.values():
            for addr in p.ip4:
                index[addr.split("/")[0]] = pr.device.key
    return index


def build_routing_adjs(polled: list[PollResult]) -> list[RoutingAdj]:
    """Turn raw OSPF/BGP neighbour records into deduplicated adjacencies.

    Peers are matched to inventory by neighbour interface IP (OSPF) or
    peer IP (BGP), falling back to OSPF router-id. Unmatched peers become
    external endpoints so eBGP uplinks and WAN routers still appear.
    """
    ip_index = build_ip_index(polled)
    adjs: dict[tuple, RoutingAdj] = {}

    for pr in polled:
        for n in pr.ospf:
            peer_key = (ip_index.get(n.get("if_addr", ""))
                        or ip_index.get(n.get("router_id", "")))
            adj = RoutingAdj(
                protocol="ospf", vrf=n.get("vrf", "default"),
                a_key=pr.device.key,
                b_key=peer_key or "",
                b_external="" if peer_key else (n.get("if_addr")
                                                or n.get("router_id") or "?"),
                detail=f"area {n.get('area', '')}",
                state=n.get("state", "").upper(),
            )
            adjs.setdefault(adj.canonical(), adj)

        for n in pr.bgp:
            peer_key = ip_index.get(n.get("peer_ip", ""))
            local_as, remote_as = n.get("local_as", ""), n.get("remote_as", "")
            if local_as and remote_as:
                if local_as == remote_as:
                    detail = f"iBGP AS {local_as}"
                else:
                    as_pair = " \u2194 ".join(sorted([local_as, remote_as]))
                    detail = f"eBGP AS {as_pair}"
            else:
                detail = f"AS {remote_as or local_as}"
            adj = RoutingAdj(
                protocol="bgp", vrf=n.get("vrf", "default"),
                a_key=pr.device.key,
                b_key=peer_key or "",
                b_external="" if peer_key else n.get("peer_ip", "?"),
                detail=detail,
                state=n.get("state", ""),
            )
            adjs.setdefault(adj.canonical(), adj)

    return list(adjs.values())


# --------------------------------------------------------------------------
# VSX pair detection
# --------------------------------------------------------------------------

def detect_vsx_pairs(polled: list[PollResult]) -> list[tuple[str, str]]:
    """Return [(key_a, key_b), ...] of VSX pairs.

    Primary match: identical configured VSX system MAC (shared by both
    members by design). Fallback: my keepalive peer IP is one of your IPs.
    Also annotates each Device's vsx_role in place.
    """
    members = [(pr, pr.vsx) for pr in polled if pr.vsx]
    for pr, vsx in members:
        pr.device.vsx_role = vsx.role

    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()

    by_mac: dict[str, list[PollResult]] = {}
    for pr, vsx in members:
        if vsx.vsx_mac:
            by_mac.setdefault(vsx.vsx_mac, []).append(pr)
    for mac, prs in by_mac.items():
        if len(prs) == 2:
            a, b = sorted(prs, key=lambda p: p.device.key)
            pairs.append((a.device.key, b.device.key))
            seen.update((a.device.key, b.device.key))
        elif len(prs) > 2:
            log.warning("VSX system MAC %s claimed by %d switches — "
                        "check for a cloned config", mac, len(prs))

    # Fallback: keepalive peer IP matching for members not paired by MAC.
    ip_index = build_ip_index(polled)
    for pr, vsx in members:
        if pr.device.key in seen or not vsx.keepalive_peer:
            continue
        peer_key = ip_index.get(vsx.keepalive_peer)
        if peer_key and peer_key not in seen and peer_key != pr.device.key:
            pairs.append(tuple(sorted([pr.device.key, peer_key])))
            seen.update((pr.device.key, peer_key))
    return pairs


# --------------------------------------------------------------------------
# Diff mode
# --------------------------------------------------------------------------

@dataclass
class TopoDiff:
    added_devices: list[str] = field(default_factory=list)
    removed_devices: list[str] = field(default_factory=list)
    added_links: list[Edge] = field(default_factory=list)
    removed_links: list[Edge] = field(default_factory=list)
    unchanged_links: list[Edge] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.added_devices or self.removed_devices
                    or self.added_links or self.removed_links)


def load_topology_json(path: str) -> Topology:
    with open(path) as f:
        data = json.load(f)
    topo = Topology()
    for d in data.get("devices", []):
        fields = {k: v for k, v in d.items()
                  if k in Device.__dataclass_fields__}
        topo.upsert_device(Device(**fields))
    for l in data.get("links", []):
        topo.add_edge(Edge(a_key=l["a"], a_port=l.get("a_port", ""),
                           b_key=l["b"], b_port=l.get("b_port", "")))
    return topo


def diff_topologies(old: Topology, new: Topology) -> TopoDiff:
    d = TopoDiff()
    d.added_devices = sorted(set(new.devices) - set(old.devices))
    d.removed_devices = sorted(set(old.devices) - set(new.devices))
    old_keys, new_keys = set(old.edges), set(new.edges)
    d.added_links = [new.edges[k] for k in sorted(new_keys - old_keys)]
    d.removed_links = [old.edges[k] for k in sorted(old_keys - new_keys)]
    d.unchanged_links = [new.edges[k] for k in sorted(new_keys & old_keys)]
    return d


def log_diff(diff: TopoDiff, old: Topology, new: Topology) -> None:
    def name(key):
        dev = new.devices.get(key) or old.devices.get(key)
        return (dev.hostname or key) if dev else key

    def link_str(e: Edge) -> str:
        return (f"{name(e.a_key)}:{e.a_port} \u2194 "
                f"{name(e.b_key)}:{e.b_port}")

    if diff.empty:
        log.info("No topology changes.")
        return
    for key in diff.added_devices:
        log.info("+ device  %s", name(key))
    for key in diff.removed_devices:
        log.info("- device  %s", name(key))
    for e in diff.added_links:
        log.info("+ link    %s", link_str(e))
    for e in diff.removed_links:
        log.info("- link    %s", link_str(e))
    log.info("Summary: +%d/-%d devices, +%d/-%d links (%d unchanged)",
             len(diff.added_devices), len(diff.removed_devices),
             len(diff.added_links), len(diff.removed_links),
             len(diff.unchanged_links))


# --------------------------------------------------------------------------
# draw.io output
# --------------------------------------------------------------------------

SWITCH_STYLE = (
    "rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;"
    "fontFamily=Helvetica;fontSize=11;align=center;"
)
ENDPOINT_STYLE = (
    "rounded=1;whiteSpace=wrap;html=1;fillColor=#f5f5f5;strokeColor=#999999;"
    "fontFamily=Helvetica;fontSize=10;align=center;dashed=1;"
)
EDGE_STYLE = (
    "endArrow=none;startArrow=none;html=1;strokeColor=#666666;"
    "fontSize=9;fontColor=#333333;labelBackgroundColor=#ffffff;"
)

NODE_W, NODE_H = 200, 60


def _layout(topo: Topology,
            vsx_pairs: list[tuple[str, str]] | None = None
            ) -> dict[str, tuple[float, float]]:
    """Switches on a circle; VSX pair members share a slot side by side;
    endpoints radially outside their switch."""
    pos: dict[str, tuple[float, float]] = {}
    switches = [d for d in topo.devices.values() if d.is_switch]
    endpoints = [d for d in topo.devices.values() if not d.is_switch]

    pair_of: dict[str, str] = {}
    for a, b in (vsx_pairs or []):
        pair_of[a] = b
        pair_of[b] = a

    # Build circle slots: one per standalone switch, one per VSX pair.
    slots: list[list[str]] = []
    placed: set[str] = set()
    for dev in sorted(switches, key=lambda d: d.hostname or d.key):
        if dev.key in placed:
            continue
        partner = pair_of.get(dev.key)
        if partner and partner in topo.devices:
            slots.append(sorted([dev.key, partner]))
            placed.update((dev.key, partner))
        else:
            slots.append([dev.key])
            placed.add(dev.key)

    n = max(len(slots), 1)
    radius = max(300.0, 110.0 * n / math.pi)
    cx = cy = radius + 300
    for i, slot in enumerate(slots):
        ang = 2 * math.pi * i / n
        x = cx + radius * math.cos(ang)
        y = cy + radius * math.sin(ang)
        if len(slot) == 1:
            pos[slot[0]] = (x, y)
        else:
            # Offset pair members tangentially so the ISL edge is short.
            tx, ty = -math.sin(ang), math.cos(ang)
            off = NODE_W / 2 + 30
            pos[slot[0]] = (x - tx * off, y - ty * off)
            pos[slot[1]] = (x + tx * off, y + ty * off)

    # Group endpoints by the switch they attach to.
    attach: dict[str, list[str]] = {}
    for edge in topo.edges.values():
        for k, other in ((edge.a_key, edge.b_key), (edge.b_key, edge.a_key)):
            if k in pos:
                continue
            if other in pos:
                attach.setdefault(other, []).append(k)

    for sw_key, ep_keys in attach.items():
        sx, sy = pos[sw_key]
        vx, vy = sx - cx, sy - cy
        norm = math.hypot(vx, vy) or 1.0
        base_ang = math.atan2(vy, vx)
        for j, ep_key in enumerate(sorted(set(ep_keys))):
            spread = (j - (len(ep_keys) - 1) / 2) * 0.35
            ang = base_ang + spread
            r = norm + 260 + 40 * (j % 2)
            pos[ep_key] = (cx + r * math.cos(ang), cy + r * math.sin(ang))

    # Anything unplaced (isolated endpoints) goes in a row at the bottom.
    stray = [d.key for d in endpoints if d.key not in pos]
    for j, key in enumerate(stray):
        pos[key] = (200 + j * (NODE_W + 40), cy + radius + 500)
    return pos


L2_EDGE_STYLE = EDGE_STYLE + "strokeWidth=2;strokeColor=#6c8ebf;"
L3_EDGE_STYLE = EDGE_STYLE + "strokeColor=#82b366;dashed=1;"
SUBNET_STYLE = (
    "ellipse;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;"
    "fontFamily=Helvetica;fontSize=10;align=center;"
)
OSPF_EDGE_STYLE = EDGE_STYLE + "strokeColor=#d79b00;strokeWidth=2;"
BGP_EDGE_STYLE = EDGE_STYLE + "strokeColor=#9673a6;strokeWidth=2;"
EXTERNAL_STYLE = (
    "rounded=1;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;"
    "fontFamily=Helvetica;fontSize=10;align=center;dashed=1;"
)
VSX_BOX_STYLE = (
    "rounded=1;whiteSpace=wrap;html=1;fillColor=none;strokeColor=#6c8ebf;"
    "dashed=1;dashPattern=8 4;verticalAlign=top;fontSize=10;"
    "fontColor=#6c8ebf;fontFamily=Helvetica;"
)
DIFF_ADDED_NODE = SWITCH_STYLE.replace(
    "fillColor=#dae8fc;strokeColor=#6c8ebf",
    "fillColor=#d5e8d4;strokeColor=#82b366")
DIFF_REMOVED_NODE = SWITCH_STYLE.replace(
    "fillColor=#dae8fc;strokeColor=#6c8ebf",
    "fillColor=#f8cecc;strokeColor=#b85450") + "dashed=1;"
DIFF_ADDED_EDGE = EDGE_STYLE + "strokeColor=#82b366;strokeWidth=2;"
DIFF_REMOVED_EDGE = EDGE_STYLE + "strokeColor=#b85450;strokeWidth=2;dashed=1;"


class _XmlBuilder:
    """Accumulates cells with unique ids across draw.io layers."""

    def __init__(self):
        self.cells: list[str] = []
        self._next = 2

    @staticmethod
    def _esc(label: str) -> str:
        # &#10; survives XML attribute-value normalisation; a literal
        # newline would be collapsed to a space by conformant parsers.
        return escape(label, {"\n": "&#10;"})

    def layer(self, layer_id: str, name: str, visible: bool) -> None:
        vis = "" if visible else ' visible="0"'
        self.cells.append(
            f'<mxCell id="{layer_id}" value="{self._esc(name)}" '
            f'style="locked=0"{vis} parent="0"/>')

    def node(self, layer: str, label: str, style: str,
             x: float, y: float, w: float = NODE_W, h: float = NODE_H) -> str:
        nid = f"n{self._next}"
        self._next += 1
        self.cells.append(
            f'<mxCell id="{nid}" value="{self._esc(label)}" style="{style}" '
            f'vertex="1" parent="{layer}">'
            f'<mxGeometry x="{x - w / 2:.0f}" y="{y - h / 2:.0f}" '
            f'width="{w:.0f}" height="{h:.0f}" as="geometry"/></mxCell>')
        return nid

    def edge(self, layer: str, label: str, style: str,
             src: str, dst: str) -> None:
        eid = f"e{self._next}"
        self._next += 1
        self.cells.append(
            f'<mxCell id="{eid}" value="{self._esc(label)}" style="{style}" '
            f'edge="1" parent="{layer}" source="{src}" target="{dst}">'
            f'<mxGeometry relative="1" as="geometry"/></mxCell>')


def to_drawio_xml(topo: Topology,
                  l2_edges: list[L2Edge] | None = None,
                  l3_segments: list[L3Segment] | None = None,
                  routing_adjs: list[RoutingAdj] | None = None,
                  vsx_pairs: list[tuple[str, str]] | None = None) -> str:
    """Emit a draw.io file with up to four toggleable layers.

    All layers reuse the same node coordinates so switching layers keeps
    each device in place. Toggle via View > Layers in draw.io.
    """
    pos = _layout(topo, vsx_pairs)
    xb = _XmlBuilder()

    def vsx_boxes(layer: str, node_keys: set) -> None:
        """Dashed container behind each VSX pair (emit before nodes)."""
        for a, b in (vsx_pairs or []):
            if a not in node_keys or b not in node_keys:
                continue
            (ax, ay), (bx, by) = pos[a], pos[b]
            x0, x1 = min(ax, bx) - NODE_W / 2, max(ax, bx) + NODE_W / 2
            y0, y1 = min(ay, by) - NODE_H / 2, max(ay, by) + NODE_H / 2
            xb.node(layer, "VSX", VSX_BOX_STYLE,
                    (x0 + x1) / 2, (y0 + y1) / 2 - 12,
                    w=(x1 - x0) + 30, h=(y1 - y0) + 54)

    # ---- Layer 1: physical (visible by default) --------------------------
    xb.layer("lyr_phys", "1 - Physical (LLDP)", visible=True)
    vsx_boxes("lyr_phys", set(topo.devices))
    phys_ids: dict[str, str] = {}
    for key, dev in topo.devices.items():
        x, y = pos.get(key, (100, 100))
        style = SWITCH_STYLE if dev.is_switch else ENDPOINT_STYLE
        phys_ids[key] = xb.node("lyr_phys", dev.label, style, x, y)
    for edge in topo.edges.values():
        src, dst = phys_ids.get(edge.a_key), phys_ids.get(edge.b_key)
        if src and dst:
            xb.edge("lyr_phys", f"{edge.a_port} \u2194 {edge.b_port}",
                    EDGE_STYLE, src, dst)

    # ---- Layer 2: L2 (LAGs + VLANs) ---------------------------------------
    if l2_edges:
        xb.layer("lyr_l2", "2 - Layer 2 (LAGs / VLANs)", visible=False)
        l2_devs = {e.a_key for e in l2_edges} | {e.b_key for e in l2_edges}
        vsx_boxes("lyr_l2", l2_devs)
        l2_ids: dict[str, str] = {}
        for key in l2_devs:
            dev = topo.devices[key]
            x, y = pos.get(key, (100, 100))
            l2_ids[key] = xb.node("lyr_l2", dev.label, SWITCH_STYLE, x, y)
        for e in l2_edges:
            bits = [f"{e.a_if} \u2194 {e.b_if}"]
            if e.member_count > 1:
                bits.append(f"{e.member_count}x links")
            if e.vlan_label:
                bits.append(e.vlan_label)
            xb.edge("lyr_l2", "\n".join(bits), L2_EDGE_STYLE,
                    l2_ids[e.a_key], l2_ids[e.b_key])

    # ---- Layer 3: L3 (VRFs / subnets) --------------------------------------
    if l3_segments:
        xb.layer("lyr_l3", "3 - Layer 3 (subnets / VRFs)", visible=False)
        l3_ids: dict[str, str] = {}
        l3_devs = {k for seg in l3_segments for k in seg.members}
        for key in l3_devs:
            dev = topo.devices.get(key)
            if dev is None:
                continue
            x, y = pos.get(key, (100, 100))
            l3_ids[key] = xb.node("lyr_l3", dev.label, SWITCH_STYLE, x, y)
        for seg in l3_segments:
            members = [k for k in seg.members if k in l3_ids]
            if len(members) < 2:
                continue
            if len(members) == 2:
                a, b = members
                label = (f"{seg.label}\n{seg.members[a]}"
                         f" \u2194 {seg.members[b]}")
                xb.edge("lyr_l3", label, L3_EDGE_STYLE,
                        l3_ids[a], l3_ids[b])
            else:
                # Shared segment: subnet hub node with spokes.
                xs = [pos[k][0] for k in members]
                ys = [pos[k][1] for k in members]
                hub = xb.node("lyr_l3", seg.label, SUBNET_STYLE,
                              sum(xs) / len(xs), sum(ys) / len(ys),
                              w=160, h=50)
                for k in members:
                    xb.edge("lyr_l3", seg.members[k], L3_EDGE_STYLE,
                            l3_ids[k], hub)

    # ---- Layer 4: routing protocols (OSPF / BGP) ---------------------------
    if routing_adjs:
        xb.layer("lyr_rtg", "4 - Routing (OSPF / BGP)", visible=False)
        rt_devs = {a.a_key for a in routing_adjs} | {
            a.b_key for a in routing_adjs if a.b_key}
        rt_ids: dict[str, str] = {}
        for key in rt_devs:
            dev = topo.devices.get(key)
            if dev is None:
                continue
            x, y = pos.get(key, (100, 100))
            rt_ids[key] = xb.node("lyr_rtg", dev.label, SWITCH_STYLE, x, y)
        # External peers: one node per unmatched IP, placed centrally.
        ext_ips = sorted({a.b_external for a in routing_adjs
                          if a.b_external})
        for j, ip in enumerate(ext_ips):
            rt_ids[f"ext:{ip}"] = xb.node(
                "lyr_rtg", f"{ip}\n(external peer)", EXTERNAL_STYLE,
                200 + (j % 4) * (NODE_W + 60),
                80 + (j // 4) * (NODE_H + 40))
        for adj in routing_adjs:
            src = rt_ids.get(adj.a_key)
            dst = rt_ids.get(adj.b_key or f"ext:{adj.b_external}")
            if not (src and dst):
                continue
            style = (OSPF_EDGE_STYLE if adj.protocol == "ospf"
                     else BGP_EDGE_STYLE)
            xb.edge("lyr_rtg", adj.label, style, src, dst)

    body = "\n        ".join(xb.cells)
    return f"""<mxfile host="lldp_mapper" type="device">
  <diagram name="Topology" id="lldp-topology">
    <mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1"
                  tooltips="1" connect="1" arrows="1" fold="1" page="1"
                  pageScale="1" pageWidth="1600" pageHeight="1200" math="0" shadow="0">
      <root>
        <mxCell id="0"/>
        {body}
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
"""


def to_diff_drawio(old: Topology, new: Topology, diff: TopoDiff) -> str:
    """Union diagram: green added, red-dashed removed, grey unchanged."""
    union = Topology()
    for topo in (new, old):
        for dev in topo.devices.values():
            union.upsert_device(Device(**{
                k: getattr(dev, k) for k in Device.__dataclass_fields__}))
    pos = _layout(union)
    xb = _XmlBuilder()
    xb.layer("lyr_diff", "Topology diff", visible=True)

    added_devs = set(diff.added_devices)
    removed_devs = set(diff.removed_devices)
    ids: dict[str, str] = {}
    for key, dev in union.devices.items():
        if key in added_devs:
            style = DIFF_ADDED_NODE
        elif key in removed_devs:
            style = DIFF_REMOVED_NODE
        elif dev.is_switch:
            style = SWITCH_STYLE
        else:
            style = ENDPOINT_STYLE
        x, y = pos.get(key, (100, 100))
        ids[key] = xb.node("lyr_diff", dev.label, style, x, y)

    for edges, style, prefix in (
            (diff.unchanged_links, EDGE_STYLE, ""),
            (diff.added_links, DIFF_ADDED_EDGE, "+ "),
            (diff.removed_links, DIFF_REMOVED_EDGE, "\u2212 ")):
        for e in edges:
            src, dst = ids.get(e.a_key), ids.get(e.b_key)
            if src and dst:
                xb.edge("lyr_diff",
                        f"{prefix}{e.a_port} \u2194 {e.b_port}",
                        style, src, dst)

    body = "\n        ".join(xb.cells)
    return f"""<mxfile host="lldp_mapper" type="device">
  <diagram name="Topology diff" id="lldp-diff">
    <mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1"
                  tooltips="1" connect="1" arrows="1" fold="1" page="1"
                  pageScale="1" pageWidth="1600" pageHeight="1200" math="0" shadow="0">
      <root>
        <mxCell id="0"/>
        {body}
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
"""


def to_json(topo: Topology,
            routing_adjs: list[RoutingAdj] | None = None,
            vsx_pairs: list[tuple[str, str]] | None = None) -> str:
    out = {
        "devices": [vars(d) for d in topo.devices.values()],
        "links": [
            {"a": e.a_key, "a_port": e.a_port, "b": e.b_key, "b_port": e.b_port}
            for e in topo.edges.values()
        ],
    }
    if vsx_pairs:
        out["vsx_pairs"] = [list(p) for p in vsx_pairs]
    if routing_adjs:
        out["routing"] = [vars(a) for a in routing_adjs]
    return json.dumps(out, indent=2)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Map an AOS-CX network via LLDP and emit a draw.io diagram.")
    sub = ap.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a subnet and map the topology")
    scan.add_argument("subnet", help="CIDR to scan, e.g. 10.20.30.0/24")
    scan.add_argument("-u", "--username", required=True)
    scan.add_argument("-o", "--output", default="topology.drawio",
                      help="draw.io output file (default: topology.drawio)")
    scan.add_argument("--json", metavar="FILE",
                      help="also write the raw topology as JSON")
    scan.add_argument("--api-version", default=DEFAULT_API_VERSION,
                      help="'auto' negotiates the latest version via GET "
                           "/rest (v10.16 on 10.16 firmware); or pin one, "
                           "e.g. v10.04 (default: auto)")
    scan.add_argument("--include-endpoints", action="store_true",
                      help="include non-switch LLDP neighbours (APs, servers, phones)")
    scan.add_argument("--physical-only", action="store_true",
                      help="skip L2/L3/routing layers (fewer API calls per switch)")
    scan.add_argument("--no-routing", action="store_true",
                      help="skip OSPF/BGP adjacency collection")
    scan.add_argument("--scan-workers", type=int, default=64)
    scan.add_argument("--poll-workers", type=int, default=8,
                      help="concurrent switch polls (keep modest: REST session limits)")
    scan.add_argument("--verify-ssl", action="store_true")
    scan.add_argument("-v", "--verbose", action="store_true")

    dif = sub.add_parser("diff",
                         help="compare two JSON inventories from --json")
    dif.add_argument("old_json")
    dif.add_argument("new_json")
    dif.add_argument("-o", "--output", default="",
                     help="write a colour-coded diff diagram (.drawio)")
    dif.add_argument("-v", "--verbose", action="store_true")

    # Back-compat: `lldp_mapper.py 10.0.0.0/24 -u admin` still works.
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in ("scan", "diff", "-h", "--help"):
        argv.insert(0, "scan")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s")

    if args.command == "diff":
        return run_diff(args)
    return run_scan(args)


def run_diff(args) -> int:
    old = load_topology_json(args.old_json)
    new = load_topology_json(args.new_json)
    diff = diff_topologies(old, new)
    log_diff(diff, old, new)
    if args.output:
        with open(args.output, "w") as f:
            f.write(to_diff_drawio(old, new, diff))
        log.info("diff diagram written to %s", args.output)
    return 0 if diff.empty else 2


def run_scan(args) -> int:
    password = os.environ.get("AOSCX_PASSWORD") or getpass.getpass(
        f"Password for {args.username}: ")

    candidates = scan_subnet(args.subnet, workers=args.scan_workers)
    if not candidates:
        log.error("No hosts responding on tcp/443 — nothing to do.")
        return 1

    want_details = not args.physical_only
    want_routing = want_details and not args.no_routing
    polled: list[PollResult] = []
    with cf.ThreadPoolExecutor(max_workers=args.poll_workers) as pool:
        futures = [
            pool.submit(poll_device, ip, args.username, password,
                        args.api_version, args.verify_ssl,
                        want_details, want_routing)
            for ip in candidates
        ]
        for fut in cf.as_completed(futures):
            result = fut.result()
            if result:
                polled.append(result)

    if not polled:
        log.error("No AOS-CX switches successfully polled.")
        return 1

    topo = build_topology(polled, include_endpoints=args.include_endpoints)

    l2_edges, l3_segments, routing_adjs, vsx_pairs = None, None, None, None
    if want_details:
        details_by_dev = {pr.device.key: pr.details for pr in polled}
        l2_edges = build_l2_edges(topo, details_by_dev)
        l3_segments = build_l3_segments(details_by_dev)
        vsx_pairs = detect_vsx_pairs(polled)
        log.info("L2 layer: %d aggregated link(s); L3 layer: %d segment(s); "
                 "VSX pairs: %d",
                 len(l2_edges), len(l3_segments), len(vsx_pairs))
    if want_routing:
        routing_adjs = build_routing_adjs(polled)
        log.info("Routing layer: %d adjacenc%s",
                 len(routing_adjs),
                 "y" if len(routing_adjs) == 1 else "ies")

    log.info("Topology: %d device(s), %d physical link(s)",
             len(topo.devices), len(topo.edges))

    with open(args.output, "w") as f:
        f.write(to_drawio_xml(topo, l2_edges, l3_segments,
                              routing_adjs, vsx_pairs))
    log.info("draw.io diagram written to %s (layers: View > Layers)",
             args.output)

    if args.json:
        with open(args.json, "w") as f:
            f.write(to_json(topo, routing_adjs, vsx_pairs))
        log.info("JSON inventory written to %s", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
