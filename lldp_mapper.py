#!/usr/bin/env python3
"""
lldp_mapper.py — AOS-CX LLDP topology mapper.

Scans a subnet for AOS-CX switches (REST API on tcp/443), pulls LLDP
neighbour data via the AOS-CX REST API, builds a deduplicated topology
graph, and emits a draw.io XML diagram.

Usage:
    python3 lldp_mapper.py scan 10.20.30.0/24 -u admin -o topology.drawio
    python3 lldp_mapper.py scan 10.20.30.0/24 --creds creds.json
    python3 lldp_mapper.py scan 10.20.30.0/24 -u admin --include-endpoints
    python3 lldp_mapper.py diff old.json new.json -o diff.drawio

Credentials: --creds JSON file and/or -u accounts. With a single -u the
password is taken from the AOSCX_PASSWORD environment variable if set,
otherwise prompted interactively (never on the CLI).

Only stdlib + requests. Designed for AOS-CX 10.04+.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
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
    active_gateway: str = ""     # VSX active-gateway VIP, if configured

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

class NotAosCxError(Exception):
    """Host has no recognisable AOS-CX REST index; no login attempted."""


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

        The index doubles as the AOS-CX fingerprint: a host that does
        not serve one (iLO, printer, firewall, ...) raises NotAosCxError
        so no credentials are ever posted to it. Pin --api-version to
        bypass the check for a switch whose index is unavailable.
        """
        try:
            r = self.session.get(f"https://{self.host}/rest",
                                 timeout=HTTP_TIMEOUT)
            r.raise_for_status()
            index = r.json()
        except ValueError as exc:      # 200 but not JSON (some web UI)
            raise NotAosCxError("/rest is not a JSON index") from exc
        except requests.HTTPError as exc:
            code = (exc.response.status_code
                    if exc.response is not None else "?")
            raise NotAosCxError(f"/rest returned HTTP {code}") from exc
        if not self.looks_like_index(index):
            raise NotAosCxError("/rest lists no API versions")
        version = self.pick_version(index)
        log.debug("%s: negotiated API version %s", self.host, version)
        return version

    @staticmethod
    def looks_like_index(index) -> bool:
        """True if a GET /rest body advertises at least one vX.Y."""
        if not isinstance(index, dict):
            return False
        latest = index.get("latest")
        if isinstance(latest, dict) and re.fullmatch(
                r"v\d+\.\d+", str(latest.get("version") or "")):
            return True
        return any(re.fullmatch(r"v\d+\.\d+", str(k)) for k in index)

    def __enter__(self) -> "AosCxRest":
        try:
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
        except BaseException:
            self.session.close()     # __exit__ is not called on failure
            raise
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
        except (requests.HTTPError, requests.Timeout) as exc:
            log.debug("%s: wildcard LLDP query failed (%s), iterating",
                      self.host, type(exc).__name__)
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
        SVIs that come back with no IPv4 address get one unfiltered
        re-fetch: some firmware has been observed to omit ip4_address
        from attribute-filtered responses on down SVIs (VLAN with no
        active members), and the full resource body still carries the
        configured address.
        """
        result = self._interface_details_raw()
        refetched = 0
        for name, p in result.items():
            if not (p.is_svi and not p.ip4):
                continue
            enc = urllib.parse.quote(name, safe="")
            try:
                full = self.get(f"/system/interfaces/{enc}",
                                params={"depth": 1})
            except requests.HTTPError:
                continue
            fixed = self._parse_port(name, full or {})
            if fixed.ip4:
                log.debug("%s: %s address only in unfiltered fetch "
                          "(down SVI?): %s", self.host, name, fixed.ip4)
                result[name] = fixed
                refetched += 1
        if refetched:
            log.info("%s: recovered addresses for %d down SVI(s) via "
                     "unfiltered re-fetch", self.host, refetched)
        if not result:
            log.warning("%s: no interface details collected — L2/L3 "
                        "views and addressing for this switch will be "
                        "empty (run with -v for the failing responses)",
                        self.host)
            return result
        # Active-gateway VIPs: fully isolated best-effort query. The
        # attribute name is unverified across firmware families, so any
        # failure here must never disturb the core collection above.
        try:
            self._collect_active_gateways(result)
        except Exception as exc:                     # noqa: BLE001
            log.debug("%s: active-gateway collection unavailable (%s)",
                      self.host, type(exc).__name__)
        return result

    def _collect_active_gateways(self, result: dict) -> None:
        svis = [n for n, p in result.items() if p.is_svi]
        if not svis:
            return

        rows, found = {}, 0
        attrs = "name,vsx_virtual_ip4"

        # Wildcard first (what _interface_details_raw uses and what
        # 10.09+ answers), then the plain collection with depth=2 for
        # firmware that rejects the wildcard.
        for path in ("/system/interfaces/*", "/system/interfaces"):
            try:
                data = self.get(path,
                                params={"attributes": attrs, "depth": 2})
            except requests.HTTPError as e:
                log.debug("%s: active-gateway query on %s failed (%s)",
                          self.host, path, e)
                continue
            for k, v in (data or {}).items():
                if isinstance(v, dict):
                    name = (v.get("name")
                            or urllib.parse.unquote(k.rsplit("/", 1)[-1]))
                    rows[name] = v
            if rows:
                break

        if not rows:
            for name in svis:
                enc = urllib.parse.quote(name, safe="")
                try:
                    v = self.get(f"/system/interfaces/{enc}",
                                 params={"attributes": attrs, "depth": 1})
                except requests.HTTPError as e:
                    log.debug("%s: %s AG query failed: %s", self.host, name, e)
                    if not rows:
                        # First per-SVI query rejected too: the attribute
                        # is unsupported here, so don't hammer every SVI.
                        return
                    continue
                if isinstance(v, dict):
                    rows[name] = v

        for name in svis:
            v = rows.get(name)
            if not isinstance(v, dict):
                continue
            if vip := self._parse_vip(v.get("vsx_virtual_ip4")):
                result[name].active_gateway = vip
                found += 1

        log.debug("%s: %d/%d SVI active-gateway VIP(s)", self.host, found, len(svis))

    def _interface_details_raw(self) -> dict[str, PortInfo]:
        try:
            data = self.get("/system/interfaces/*",
                            params={"attributes": self.IF_ATTRS,
                                    "depth": 2})
            return {urllib.parse.unquote(k): self._parse_port(
                        urllib.parse.unquote(k), v)
                    for k, v in (data or {}).items() if isinstance(v, dict)}
        except (requests.HTTPError, requests.Timeout) as exc:
            log.debug("%s: wildcard interface query failed (%s), iterating",
                      self.host, type(exc).__name__)
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
    def _parse_vip(vip) -> str:
        if isinstance(vip, list) and vip:
            return str(vip[0]).split("/")[0]
        if isinstance(vip, dict) and vip:
            return str(next(iter(vip))).split("/")[0]
        if isinstance(vip, str) and vip:
            return vip.split("/")[0]
        return ""

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


def poll_device(ip: str, credentials: list[tuple[str, str]],
                api_version: str, verify: bool, want_details: bool = True,
                want_routing: bool = True) -> PollResult | None:
    """Log into one switch and gather everything in a single session.

    Credentials are (username, password) pairs tried in order. Only an
    authentication rejection (HTTP 401) advances to the next pair —
    connection failures and other errors abort the device immediately,
    so unreachable hosts don't burn attempts against lockout policies.
    """
    for username, password in credentials:
        details: dict[str, PortInfo] = {}
        vsx: VsxInfo | None = None
        ospf: list[dict] = []
        bgp: list[dict] = []
        try:
            with AosCxRest(ip, username, password,
                           api_version, verify) as api:
                negotiated = api.api_version
                sysinfo = api.system_info()
                lldp = api.lldp_neighbors()
                if want_details:
                    details = api.interface_details()
                    vsx = api.vsx_info()
                if want_routing:
                    ospf = api.ospf_neighbors()
                    bgp = api.bgp_neighbors()
        except NotAosCxError as exc:
            log.warning("%s: not AOS-CX (%s) — skipping, no login "
                        "attempted (pin --api-version to force)", ip, exc)
            return None
        except requests.HTTPError as exc:
            code = (exc.response.status_code
                    if exc.response is not None else 0)
            if code == 401:
                log.debug("%s: auth rejected for '%s', trying next "
                          "credential", ip, username)
                continue
            log.warning("%s: REST error %s — skipping (not AOS-CX?)",
                        ip, code or "?")
            return None
        except requests.RequestException as exc:
            log.warning("%s: unreachable via REST (%s)",
                        ip, type(exc).__name__)
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
        log.info("%s (%s, %s, user '%s'): %d LLDP neighbour(s) on %d "
                 "interface(s)", dev.hostname or ip, ip, negotiated,
                 username, n_nbrs, len(lldp))
        return PollResult(device=dev, lldp=lldp, details=details,
                          vsx=vsx, ospf=ospf, bgp=bgp)

    log.warning("%s: all %d credential(s) rejected — skipping",
                ip, len(credentials))
    return None


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
    elif p.vlan_mode.startswith("native"):
        # AOS-CX: an empty vlan_trunks on a trunk port means "allowed all".
        parts.append("trunk all")
    if p.native_vlan is not None:
        parts.append(f"native {p.native_vlan}")
    return " · ".join(parts)


def build_l2_edges(topo: Topology,
                   details_by_dev: dict[str, dict[str, PortInfo]],
                   include_endpoints: bool = False) -> list[L2Edge]:
    """Collapse physical links into LAG-level L2 links with VLAN labels.

    Switch-to-switch links always included. With include_endpoints,
    links to non-switch neighbours (APs, phones, servers) are also
    shown, labelled with the switch-side port's VLAN config — useful
    for single-switch/stack environments that have no inter-switch
    links, and for auditing edge-port membership generally.
    """
    grouped: dict[tuple, L2Edge] = {}
    for edge in topo.edges.values():
        da = topo.devices.get(edge.a_key)
        db = topo.devices.get(edge.b_key)
        if not (da and db):
            continue
        both_switches = da.is_switch and db.is_switch
        if not both_switches and not (include_endpoints
                                      and (da.is_switch or db.is_switch)):
            continue
        det_a = details_by_dev.get(edge.a_key, {})
        det_b = details_by_dev.get(edge.b_key, {})
        # LAG resolution only applies where we have the switch's config.
        if_a = _member_to_lag(det_a).get(edge.a_port, edge.a_port)
        if_b = _member_to_lag(det_b).get(edge.b_port, edge.b_port)

        ends = sorted([(edge.a_key, if_a), (edge.b_key, if_b)])
        key = (ends[0], ends[1])
        if key in grouped:
            grouped[key].member_count += 1
            continue
        # VLAN config lives on the aggregated interface (LAG or port),
        # read from whichever side is a switch we polled.
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

    proto_note: str = ""                # e.g. "OSPF FULL" when merged

    @property
    def label(self) -> str:
        vrf = "" if self.vrf == "default" else f"vrf {self.vrf} · "
        base = f"{vrf}{self.network}"
        return f"{base}\n{self.proto_note}" if self.proto_note else base


def build_l3_segments(details_by_dev: dict[str, dict[str, PortInfo]],
                      include_single: bool = False) -> list[L3Segment]:
    """Group SVI/routed-port IPs into shared (vrf, subnet) segments.

    By default only segments connecting 2+ devices are returned — the
    L3 page shows adjacency. With include_single, subnets attached to
    just one device (SVIs unique to a switch, uplink /30s to unpolled
    routers) are also returned, rendered as leaf subnet nodes; this is
    what gives a single switch or stack a meaningful L3 page.
    """
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
                detail = f"{p.name} \u00b7 {iface.ip}"
                if p.is_svi and p.svi_vlan is not None:
                    detail = f"vlan {p.svi_vlan} · {iface.ip}"
                seg.members[dev_key] = detail
    min_members = 1 if include_single else 2
    return [s for s in segments.values() if len(s.members) >= min_members]


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


def _switch_adjacency(topo: Topology) -> dict[str, set[str]]:
    adj: dict[str, set[str]] = {d.key: set() for d in topo.devices.values()
                                if d.is_switch}
    for e in topo.edges.values():
        if e.a_key in adj and e.b_key in adj:
            adj[e.a_key].add(e.b_key)
            adj[e.b_key].add(e.a_key)
    return adj


def _bfs_depths(adj: dict[str, set[str]], roots: list[str]) -> dict[str, int]:
    depths = {r: 0 for r in roots}
    frontier = list(roots)
    while frontier:
        nxt = []
        for n in frontier:
            for m in adj.get(n, ()):
                if m not in depths:
                    depths[m] = depths[n] + 1
                    nxt.append(m)
        frontier = nxt
    return depths


def _graph_centre(adj: dict[str, set[str]], nodes: list[str]) -> list[str]:
    """Core detection by iterative minimum-degree peeling.

    Repeatedly strip the current minimum-degree switches; the last
    surviving set is the core. Robust where eccentricity is not:
    dual-homed campus designs collapse the graph diameter to ~2, making
    every node a 'centre' by eccentricity, while peeling still removes
    access first (fewest uplinks), then aggregation, leaving the core.
    Degenerate topologies (rings, full meshes) tie on the final round
    and return that whole set — an honest single tier.
    """
    remaining = set(nodes)
    while remaining:
        deg = {n: len(adj.get(n, set()) & remaining) for n in remaining}
        m = min(deg.values())
        peel = {n for n, d in deg.items() if d == m}
        if peel == remaining:
            return sorted(remaining)
        remaining -= peel
    return sorted(nodes)  # unreachable, defensive


def _pair_map(vsx_pairs: list[tuple[str, str]] | None) -> dict[str, str]:
    pair_of: dict[str, str] = {}
    for a, b in (vsx_pairs or []):
        pair_of[a] = b
        pair_of[b] = a
    return pair_of


def _resolve_core_hints(topo: Topology,
                        core_hints: list[str] | None) -> set[str]:
    """Map --core values (hostname, mgmt IP or device key) to keys."""
    hints: set[str] = set()
    for h in (core_hints or []):
        hl = h.lower()
        for dev in topo.devices.values():
            if dev.is_switch and hl in ((dev.hostname or "").lower(),
                                        dev.mgmt_ip, dev.key):
                hints.add(dev.key)
    return hints


@dataclass
class ScopeInfo:
    tier: dict[str, int] = field(default_factory=dict)      # key -> depth
    block: dict[str, int] = field(default_factory=dict)     # key -> block id
    block_label: dict[int, str] = field(default_factory=dict)
    core_keys: set = field(default_factory=set)

    def splittable(self) -> bool:
        return (len(self.block_label) >= 2
                and max(self.tier.values(), default=0) >= 2)


def _block_name(hostnames: list[str]) -> str:
    common = os.path.commonprefix(hostnames).rstrip("-_")
    return common if len(common) >= 3 else "/".join(hostnames)


def classify_scopes(topo: Topology,
                    vsx_pairs: list[tuple[str, str]] | None = None,
                    core_hints: list[str] | None = None) -> ScopeInfo:
    """Tier every switch (core=0) and assign tier-2+ switches to the
    distribution block of their dominant tier-1 parent unit."""
    info = ScopeInfo()
    adj = _switch_adjacency(topo)
    if not adj:
        return info
    pair_of = _pair_map(vsx_pairs)
    hints = _resolve_core_hints(topo, core_hints)
    nodes = sorted(adj)
    roots = sorted(hints & set(nodes)) or _graph_centre(adj, nodes)
    roots = sorted(set(roots) | {pair_of[r] for r in roots
                                 if pair_of.get(r) in adj})
    info.core_keys = set(roots)
    info.tier = _bfs_depths(adj, roots)
    for n in nodes:
        info.tier.setdefault(n, 99)

    # Block units = VSX-paired (or single) tier-1 switches.
    t1 = sorted((n for n in nodes if info.tier[n] == 1),
                key=lambda k: topo.devices[k].hostname or k)
    used: set = set()
    for n in t1:
        if n in used:
            continue
        p = pair_of.get(n)
        unit = (sorted([n, p], key=lambda k: _unit_key(topo, k))
                if (p in t1 and p not in used) else [n])
        used.update(unit)
        bid = len(info.block_label)
        info.block_label[bid] = _block_name(
            [topo.devices[k].hostname or k for k in unit])
        for k in unit:
            info.block[k] = bid

    # Deeper tiers inherit the block of their dominant known parent.
    for t in range(2, max(info.tier.values()) + 1):
        for n in (m for m in nodes if info.tier[m] == t):
            votes: dict[int, int] = {}
            for m in adj[n]:
                if info.tier.get(m) == t - 1 and m in info.block:
                    b = info.block[m]
                    votes[b] = votes.get(b, 0) + 1
            if votes:
                info.block[n] = min(votes, key=lambda k: (-votes[k], k))
    return info


def _port_sort_key(port: str) -> tuple:
    """Natural sort for interface names: 1/1/2 before 1/1/10.

    The leading class digit keeps physical ports, LAGs and anything
    else in separate bands. Without it the bare number tuples compare
    across kinds by length -- lag1 -> (1,) sorts ahead of 1/1/1 ->
    (1,1,1) while lag256 sorts behind it, so a parent with a mix of
    LAG and physical uplinks orders its children incoherently.
    """
    name = (port or "").strip()
    nums = tuple(int(x) for x in re.findall(r"\d+", name))
    if not nums:
        return (2, (10**9,))
    if name.lower().startswith("lag"):
        return (1, nums)
    return (0, nums)


def _name_sort_key(name: str) -> tuple:
    """Natural sort for hostnames: sw-2 before sw-10, case-insensitive.

    Used to order VSX pair members so the -01/-a device is always the
    left-hand / primary one. Sorting on the chassis MAC instead makes
    the member order arbitrary and inconsistent between pairs.
    """
    parts = re.split(r"(\d+)", (name or "").lower())
    return tuple((1, int(p)) if p.isdigit() else (0, p)
                 for p in parts if p != "")


def _unit_key(topo: "Topology", key: str) -> tuple:
    return _name_sort_key(topo.devices[key].hostname or key)


TIER_H = 280.0        # vertical distance between tiers
UNIT_W = NODE_W + 90  # horizontal slot per switch
EP_COLS = 4           # endpoints per row in the grid under a switch
EP_W = NODE_W + 20    # horizontal slot per endpoint
EP_ROW_H = NODE_H + 20
EP_Y0 = 150.0         # switch centre -> first endpoint row centre


def _endpoints_by_switch(topo: Topology, adj: dict[str, set[str]]
                         ) -> dict[str, list[str]]:
    """{switch_key: [endpoint keys]} ordered by the switch-side port.

    An endpoint seen by several switches (dual-homed server on a VSX
    pair) is drawn under the first by hostname.
    """
    seen: dict[str, tuple] = {}
    for e in topo.edges.values():
        for ep, sw, port in ((e.a_key, e.b_key, e.b_port),
                             (e.b_key, e.a_key, e.a_port)):
            if ep in adj or sw not in adj or ep not in topo.devices:
                continue
            cand = (topo.devices[sw].hostname or sw, sw,
                    _port_sort_key(port), ep)
            if ep not in seen or cand < seen[ep]:
                seen[ep] = cand
    out: dict[str, list[str]] = {}
    for _, sw, _, ep in sorted(seen.values()):
        out.setdefault(sw, []).append(ep)
    return out


def _layout_tiered(topo: Topology,
                   vsx_pairs: list[tuple[str, str]] | None = None,
                   core_hints: list[str] | None = None
                   ) -> dict[str, tuple[float, float]]:
    """Hierarchical rows: core on top (graph centre or --core hints),
    each further tier one BFS hop down. VSX pairs are kept adjacent as
    single units. Endpoints sit in a grid under their switch; the
    switch's slot widens and the gap to the next tier deepens to make
    room, so endpoints never overlap neighbours or the tier below."""
    pos: dict[str, tuple[float, float]] = {}
    adj = _switch_adjacency(topo)
    switches = list(adj.keys())
    if not switches:
        return _layout_circle(topo, vsx_pairs)

    pair_of = _pair_map(vsx_pairs)
    hints = _resolve_core_hints(topo, core_hints)
    eps_of = _endpoints_by_switch(topo, adj)

    def slot_w(n: str) -> float:
        cols = min(len(eps_of.get(n, ())), EP_COLS)
        return max(UNIT_W, cols * EP_W + 30)

    def ep_rows(n: str) -> int:
        return math.ceil(len(eps_of.get(n, ())) / EP_COLS)

    # Components laid out side by side.
    unvisited = set(switches)
    comp_x0 = 200.0
    top_y = 150.0
    while unvisited:
        seed = sorted(unvisited)[0]
        comp = set(_bfs_depths(adj, [seed]))
        comp &= unvisited
        unvisited -= comp
        comp_nodes = sorted(comp)

        roots = sorted(hints & comp) or _graph_centre(adj, comp_nodes)
        # A VSX partner of any root is core too, whatever detection says.
        roots = sorted(set(roots) | {pair_of[r] for r in roots
                                     if pair_of.get(r) in comp})
        if hints & comp:
            note = ""
        elif len(roots) > 2:
            note = (" (auto-detected, but %d switches tied — pin the real "
                    "core with --core)" % len(roots))
        else:
            note = " (auto-detected; override with --core)"
        log.info("tiered layout: core tier = %s%s",
                 ", ".join(topo.devices[r].hostname or r for r in roots),
                 note)
        depths = _bfs_depths(adj, roots)
        # Unreached members (shouldn't happen within a component) -> deepest
        maxd = max((depths.get(n, 0) for n in comp_nodes), default=0)
        tiers: dict[int, list[str]] = {}
        for n in comp_nodes:
            tiers.setdefault(depths.get(n, maxd + 1), []).append(n)

        # Collapse VSX pairs into units per tier.
        def units_of(row: list[str]) -> list[list[str]]:
            units, used = [], set()
            for n in sorted(row, key=lambda k: (topo.devices[k].hostname
                                                or k)):
                if n in used:
                    continue
                p = pair_of.get(n)
                if p in row and p not in used:
                    units.append(sorted([n, p],
                                        key=lambda k: _unit_key(topo, k)))
                    used.update((n, p))
                else:
                    units.append([n])
                    used.add(n)
            return units

        unit_rows = {t: units_of(row) for t, row in tiers.items()}

        # Barycentric ordering: place units under the mean slot of their
        # neighbours in the tier above; two top-down passes suffice here.
        # Distribution-block grouping: below the core tier, cluster each
        # unit under its dominant parent unit (most uplinks), keep blocks
        # in the parents' order, then align parents over their children
        # bottom-up (classic tree layout) so each agg pair sits directly
        # above its own access block.
        min_t, max_t = min(unit_rows), max(unit_rows)
        parent_unit_idx: dict[str, int] = {}
        for i, unit in enumerate(unit_rows[min_t]):
            for n in unit:
                parent_unit_idx[n] = i
        group_of: dict[int, dict[int, list[list[str]]]] = {}
        for t in sorted(unit_rows):
            if t == min_t:
                continue
            groups: dict[int, list[list[str]]] = {}
            for unit in unit_rows[t]:
                votes: dict[int, int] = {}
                for n in unit:
                    for m in adj[n]:
                        if depths.get(m, 99) == t - 1:
                            pi = parent_unit_idx.get(m)
                            if pi is not None:
                                votes[pi] = votes.get(pi, 0) + 1
                best = (min(votes, key=lambda k: (-votes[k], k))
                        if votes else 10**6)
                groups.setdefault(best, []).append(unit)
            # Within a group, order children by the interface number on
            # the PRIMARY parent (first member of the parent unit by
            # hostname, i.e. the -01/-a device). Taking the minimum
            # across both VSX members is wrong under crossed patching:
            # a child on core-01:1/1/2 + core-02:1/1/1 must sort by
            # 1/1/2, not steal first place via core-02.
            def uplink_port_key(unit, parent_unit):
                """Order children by their uplink port on THIS block's
                parent, preferring the primary (-01/-a) member.

                Every child in a block must be measured against the
                same physical switch. Picking the reference parent per
                child (e.g. whichever of its neighbours sorts first by
                hostname) compares core-01's port numbers against
                core-02's, so a switch cabled to core-02:1/1/1 jumps
                ahead of one on core-01:1/1/2. Children with no link
                to the primary fall to the secondary and sort after
                the primary-homed ones, in the secondary's port order.
                """
                unit_set = set(unit)
                ports_by_parent: dict[str, tuple] = {}
                for e in topo.edges.values():
                    for child, parent, pport in (
                            (e.a_key, e.b_key, e.b_port),
                            (e.b_key, e.a_key, e.a_port)):
                        if (child in unit_set
                                and depths.get(parent, 99) == t - 1):
                            k = _port_sort_key(pport)
                            if k < ports_by_parent.get(parent, (10**9,)):
                                ports_by_parent[parent] = k
                # parent_unit is already hostname-ordered, so index 0 is
                # the primary. Fall back to any other parent last.
                candidates = list(parent_unit) + sorted(
                    (p for p in ports_by_parent if p not in parent_unit),
                    key=lambda p: _unit_key(topo, p))
                for rank, parent in enumerate(candidates):
                    if parent in ports_by_parent:
                        return (rank, ports_by_parent[parent],
                                _unit_key(topo, unit[0]))
                return (10**9, (10**9,), _unit_key(topo, unit[0]))
            ordered: list[list[str]] = []
            for gi in sorted(groups):
                parent_unit = (unit_rows[t - 1][gi]
                               if gi < len(unit_rows.get(t - 1, [])) else [])
                ordered.extend(sorted(
                    groups[gi],
                    key=lambda u, pu=parent_unit: uplink_port_key(u, pu)))
            unit_rows[t] = ordered
            group_of[t] = groups
            for i, unit in enumerate(ordered):
                for n in unit:
                    parent_unit_idx[n] = i

        BLOCK_GAP = UNIT_W * 0.7

        def unit_w(u) -> float:
            return sum(slot_w(n) for n in u)

        # Deepest row: sequential, gap between blocks.
        centre: dict[int, list[float]] = {}
        x = 0.0
        boundaries: set[int] = set()
        if max_t in group_of:
            acc = 0
            for gi in sorted(group_of[max_t])[:-1]:
                acc += len(group_of[max_t][gi])
                boundaries.add(acc)
        centre[max_t] = []
        for i, unit in enumerate(unit_rows[max_t]):
            if i in boundaries:
                x += BLOCK_GAP
            centre[max_t].append(x + unit_w(unit) / 2)
            x += unit_w(unit)

        # Upper rows: parent over the mean of its children, collisions
        # pushed right, then the row is nudged back to balance.
        for t in range(max_t - 1, min_t - 1, -1):
            child_groups = group_of.get(t + 1, {})
            desired = []
            for i, unit in enumerate(unit_rows[t]):
                kids = child_groups.get(i, [])
                if kids:
                    idxs = [unit_rows[t + 1].index(u) for u in kids]
                    desired.append(sum(centre[t + 1][j] for j in idxs)
                                   / len(idxs))
                else:
                    desired.append(None)
            row: list[float] = []
            for i, unit in enumerate(unit_rows[t]):
                want = desired[i]
                minimum = (row[-1] + unit_w(unit_rows[t][i - 1]) / 2
                           + unit_w(unit) / 2 + 20) if row else -1e18
                if want is None:
                    want = minimum if row else 0.0
                row.append(max(want, minimum))
            # If collisions pushed the row right of its targets, shift
            # the whole row back by the mean overshoot.
            offsets = [r - d for r, d in zip(row, desired)
                       if d is not None]
            if offsets:
                shift = sum(offsets) / len(offsets)
                row = [r - shift for r in row]
            centre[t] = row

        # Emit coordinates, normalised so the component starts at comp_x0.
        min_x = min(c - unit_w(u) / 2
                    for t in unit_rows
                    for c, u in zip(centre[t], unit_rows[t]))
        span = max(c + unit_w(u) / 2
                   for t in unit_rows
                   for c, u in zip(centre[t], unit_rows[t])) - min_x
        y = top_y
        for t in sorted(unit_rows):
            for c, unit in zip(centre[t], unit_rows[t]):
                x = comp_x0 + (c - min_x) - unit_w(unit) / 2
                for n in unit:
                    pos[n] = (x + slot_w(n) / 2, y)
                    x += slot_w(n)
            # Deepen the gap below a tier that carries endpoint rows.
            rows = max((ep_rows(n) for u in unit_rows[t] for n in u),
                       default=0)
            y += max(TIER_H, EP_Y0 + rows * EP_ROW_H + 70) if rows else TIER_H
        comp_x0 += span + 1.5 * UNIT_W

    # Endpoints: a grid of up to EP_COLS columns under their switch,
    # in switch-port order, each row centred on the switch.
    for sw, eps in eps_of.items():
        sx, sy = pos[sw]
        for i, ep in enumerate(eps):
            r, c = divmod(i, EP_COLS)
            in_row = min(EP_COLS, len(eps) - r * EP_COLS)
            pos[ep] = (sx + (c - (in_row - 1) / 2) * EP_W,
                       sy + EP_Y0 + r * EP_ROW_H)
    # Stray devices with no placed neighbour: one row under everything.
    stray = [d.key for d in topo.devices.values() if d.key not in pos]
    stray_y = max((p[1] for p in pos.values()), default=top_y) + TIER_H
    for j, key in enumerate(stray):
        pos[key] = (200 + j * (NODE_W + 40), stray_y)
    return pos


def _layout(topo: Topology,
            vsx_pairs: list[tuple[str, str]] | None = None,
            mode: str = "tiered",
            core_hints: list[str] | None = None
            ) -> dict[str, tuple[float, float]]:
    if mode == "circle":
        return _layout_circle(topo, vsx_pairs)
    return _layout_tiered(topo, vsx_pairs, core_hints)


def _layout_circle(topo: Topology,
            vsx_pairs: list[tuple[str, str]] | None = None
            ) -> dict[str, tuple[float, float]]:
    """Switches on a circle; VSX pair members share a slot side by side;
    endpoints radially outside their switch."""
    pos: dict[str, tuple[float, float]] = {}
    switches = [d for d in topo.devices.values() if d.is_switch]
    endpoints = [d for d in topo.devices.values() if not d.is_switch]

    pair_of = _pair_map(vsx_pairs)

    # Build circle slots: one per standalone switch, one per VSX pair.
    slots: list[list[str]] = []
    placed: set[str] = set()
    for dev in sorted(switches, key=lambda d: d.hostname or d.key):
        if dev.key in placed:
            continue
        partner = pair_of.get(dev.key)
        if partner and partner in topo.devices:
            slots.append(sorted([dev.key, partner],
                                key=lambda k: _unit_key(topo, k)))
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


L2_EDGE_STYLE = EDGE_STYLE + "strokeWidth=2;strokeColor=#6c8ebf;curved=1;"
L3_EDGE_STYLE = EDGE_STYLE + "strokeColor=#82b366;dashed=1;curved=1;"
SUBNET_STYLE = (
    "ellipse;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;"
    "fontFamily=Helvetica;fontSize=10;align=center;"
)
OSPF_EDGE_STYLE = EDGE_STYLE + "strokeColor=#d79b00;strokeWidth=2;curved=1;"
BGP_EDGE_STYLE = EDGE_STYLE + "strokeColor=#9673a6;strokeWidth=2;curved=1;"
OSPF_HUB_STYLE = (
    "ellipse;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;"
    "fontFamily=Helvetica;fontSize=10;align=center;"
)
BGP_HUB_STYLE = (
    "ellipse;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;"
    "fontFamily=Helvetica;fontSize=10;align=center;"
)
EXTERNAL_STYLE = (
    "rounded=1;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;"
    "fontFamily=Helvetica;fontSize=10;align=center;dashed=1;"
)
VSX_BOX_STYLE = (
    "rounded=1;whiteSpace=wrap;html=1;fillColor=none;strokeColor=#6c8ebf;"
    "dashed=1;dashPattern=8 4;verticalAlign=top;fontSize=10;"
    "fontColor=#6c8ebf;fontFamily=Helvetica;"
)
ADJ_DOWN_EDGE_STYLE = (EDGE_STYLE + "strokeColor=#b85450;strokeWidth=2;"
                       "dashed=1;curved=1;fontColor=#b85450;")
# Adjacency states that are normal at rest; anything else (INIT,
# EXSTART, Idle, Active, ...) is drawn explicitly even inside a hub.
HEALTHY_ADJ_STATES = {"", "FULL", "TWO_WAY", "TWOWAY", "2WAY", "2-WAY",
                      "ESTABLISHED"}


def _adj_healthy(adj: RoutingAdj) -> bool:
    return adj.state.upper().replace(" ", "_") in HEALTHY_ADJ_STATES


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
        # Double quotes are escaped so a label can't break out of the
        # value attribute.
        return escape(label, {"\n": "&#10;", '"': "&quot;"})

    @classmethod
    def _esc_html(cls, label: str) -> str:
        # Cell labels render as HTML (html=1) and carry LLDP-supplied
        # text any attached device can set, so neutralise markup first,
        # then escape the result for the XML attribute.
        return cls._esc(escape(label))

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
            f'<mxCell id="{nid}" value="{self._esc_html(label)}" style="{style}" '
            f'vertex="1" parent="{layer}">'
            f'<mxGeometry x="{x - w / 2:.0f}" y="{y - h / 2:.0f}" '
            f'width="{w:.0f}" height="{h:.0f}" as="geometry"/></mxCell>')
        return nid

    def edge(self, layer: str, label: str, style: str,
             src: str, dst: str,
             src_label: str = "", dst_label: str = "",
             waypoint: tuple[float, float] | None = None,
             labels_as_tooltip: bool = False) -> None:
        """Draw an edge; optional src/dst labels render at each end.

        With labels_as_tooltip, end labels become a hover tooltip on
        the edge instead of printed text — used automatically on large
        estates where printed port labels make the overview unreadable.

        End labels are draw.io child cells parented to the edge with
        relative geometry: x=-0.75 sits near the source node, x=+0.75
        near the target — so each port number appears beside the switch
        it belongs to, removing any which-end-is-which ambiguity.

        A waypoint bows the edge through that coordinate, used to fan
        out per-layer edges so overlaid layers stay readable.
        """
        eid = f"e{self._next}"
        self._next += 1
        wp = ""
        if waypoint is not None:
            wp = (f'<Array as="points"><mxPoint x="{waypoint[0]:.0f}" '
                  f'y="{waypoint[1]:.0f}"/></Array>')
        if labels_as_tooltip and (src_label or dst_label):
            tip = f"{src_label} \u2194 {dst_label}".strip(" \u2194 ")
            self.cells.append(
                f'<object label="{self._esc_html(label)}" '
                f'tooltip="{self._esc(tip)}" id="{eid}">'
                f'<mxCell style="{style}" edge="1" parent="{layer}" '
                f'source="{src}" target="{dst}">'
                f'<mxGeometry relative="1" as="geometry">{wp}</mxGeometry>'
                f'</mxCell></object>')
            return
        self.cells.append(
            f'<mxCell id="{eid}" value="{self._esc_html(label)}" style="{style}" '
            f'edge="1" parent="{layer}" source="{src}" target="{dst}">'
            f'<mxGeometry relative="1" as="geometry">{wp}</mxGeometry>'
            f'</mxCell>')
        for text, xpos in ((src_label, -0.75), (dst_label, 0.75)):
            if not text:
                continue
            lid = f"el{self._next}"
            self._next += 1
            self.cells.append(
                f'<mxCell id="{lid}" value="{self._esc_html(text)}" '
                f'style="edgeLabel;html=1;align=center;verticalAlign=middle;'
                f'resizable=0;points=[];fontSize=9;fontColor=#333333;'
                f'labelBackgroundColor=#ffffff;" '
                f'vertex="1" connectable="0" parent="{eid}">'
                f'<mxGeometry x="{xpos}" relative="1" as="geometry">'
                f'<mxPoint as="offset"/></mxGeometry></mxCell>')


def _bow(pos: dict, key_a: str, key_b: str, offset: float
         ) -> tuple[float, float] | None:
    """Midpoint displaced perpendicular to the a->b line (layered mode)."""
    if offset == 0 or key_a not in pos or key_b not in pos:
        return None
    (ax, ay), (bx, by) = pos[key_a], pos[key_b]
    dx, dy = bx - ax, by - ay
    norm = math.hypot(dx, dy)
    if norm < 1:
        return None
    px, py = -dy / norm, dx / norm
    return ((ax + bx) / 2 + px * offset, (ay + by) / 2 + py * offset)


def _vsx_boxes(xb: "_XmlBuilder", parent: str, pos: dict,
               vsx_pairs: list[tuple[str, str]] | None,
               node_keys: set) -> None:
    """Dashed container behind each VSX pair (emit before nodes)."""
    for a, b in (vsx_pairs or []):
        if a not in node_keys or b not in node_keys:
            continue
        if a not in pos or b not in pos:
            continue
        (ax, ay), (bx, by) = pos[a], pos[b]
        x0, x1 = min(ax, bx) - NODE_W / 2, max(ax, bx) + NODE_W / 2
        y0, y1 = min(ay, by) - NODE_H / 2, max(ay, by) + NODE_H / 2
        xb.node(parent, "VSX", VSX_BOX_STYLE,
                (x0 + x1) / 2, (y0 + y1) / 2 - 12,
                w=(x1 - x0) + 30, h=(y1 - y0) + 54)


DETAIL_LABEL_MAX_SWITCHES = 15


def _render_physical(xb: "_XmlBuilder", parent: str, topo: Topology,
                     pos: dict,
                     vsx_pairs: list[tuple[str, str]] | None,
                     detail: bool = True) -> None:
    _vsx_boxes(xb, parent, pos, vsx_pairs, set(topo.devices))
    ids: dict[str, str] = {}
    for key, dev in topo.devices.items():
        x, y = pos.get(key, (100, 100))
        style = SWITCH_STYLE if dev.is_switch else ENDPOINT_STYLE
        ids[key] = xb.node(parent, dev.label, style, x, y)
    for edge in topo.edges.values():
        src, dst = ids.get(edge.a_key), ids.get(edge.b_key)
        if src and dst:
            xb.edge(parent, "", EDGE_STYLE, src, dst,
                    src_label=edge.a_port, dst_label=edge.b_port,
                    labels_as_tooltip=not detail)


def _render_l2(xb: "_XmlBuilder", parent: str, topo: Topology, pos: dict,
               l2_edges: list[L2Edge],
               vsx_pairs: list[tuple[str, str]] | None,
               bow_offset: float = 0.0, detail: bool = True) -> None:
    l2_devs = {e.a_key for e in l2_edges} | {e.b_key for e in l2_edges}
    _vsx_boxes(xb, parent, pos, vsx_pairs, l2_devs)
    ids: dict[str, str] = {}
    for key in sorted(l2_devs):
        dev = topo.devices.get(key)
        if dev is None:
            continue
        x, y = pos.get(key, (100, 100))
        style = SWITCH_STYLE if dev.is_switch else ENDPOINT_STYLE
        ids[key] = xb.node(parent, dev.label, style, x, y)
    for e in l2_edges:
        bits = []
        if e.member_count > 1:
            bits.append(f"{e.member_count}x links")
        if e.vlan_label:
            bits.append(e.vlan_label)
        if e.a_key not in ids or e.b_key not in ids:
            continue
        xb.edge(parent, "\n".join(bits), L2_EDGE_STYLE,
                ids[e.a_key], ids[e.b_key],
                src_label=e.a_if, dst_label=e.b_if,
                waypoint=_bow(pos, e.a_key, e.b_key, bow_offset),
                labels_as_tooltip=not detail)


def _render_l3(xb: "_XmlBuilder", parent: str, topo: Topology, pos: dict,
               l3_segments: list[L3Segment],
               bow_offset: float = 0.0, detail: bool = True) -> None:
    ids: dict[str, str] = {}
    l3_devs = {k for seg in l3_segments for k in seg.members}
    for key in sorted(l3_devs):
        dev = topo.devices.get(key)
        if dev is None:
            continue
        x, y = pos.get(key, (100, 100))
        ids[key] = xb.node(parent, dev.label, SWITCH_STYLE, x, y)
    # Leaf subnets (single member) fan out around their switch.
    leaf_count: dict[str, int] = {}
    for seg in l3_segments:
        members = [k for k in seg.members if k in ids]
        if len(members) < 1:
            continue
        if len(members) == 1:
            k = members[0]
            j = leaf_count.get(k, 0)
            leaf_count[k] = j + 1
            sx, sy = pos.get(k, (100, 100))
            ang = -math.pi / 2 + j * (math.pi / 5)
            lx = sx + 260 * math.cos(ang)
            ly = sy + 260 * math.sin(ang)
            leaf = xb.node(parent, seg.label, SUBNET_STYLE, lx, ly,
                           w=160, h=50)
            xb.edge(parent, "", L3_EDGE_STYLE, ids[k], leaf,
                    dst_label=seg.members[k])
        elif len(members) == 2:
            a, b = members
            xb.edge(parent, seg.label, L3_EDGE_STYLE, ids[a], ids[b],
                    src_label=seg.members[a], dst_label=seg.members[b],
                    waypoint=_bow(pos, a, b, bow_offset),
                    labels_as_tooltip=not detail)
        else:
            xs = [pos[k][0] for k in members]
            ys = [pos[k][1] for k in members]
            hub = xb.node(parent, seg.label, SUBNET_STYLE,
                          sum(xs) / len(xs), sum(ys) / len(ys),
                          w=160, h=50)
            for k in members:
                xb.edge(parent, seg.members[k], L3_EDGE_STYLE, ids[k], hub)


def _render_routing(xb: "_XmlBuilder", parent: str, topo: Topology,
                    pos: dict, routing_adjs: list[RoutingAdj],
                    bow_offset: float = 0.0) -> None:
    rt_devs = {a.a_key for a in routing_adjs} | {
        a.b_key for a in routing_adjs if a.b_key}
    ids: dict[str, str] = {}
    for key in sorted(rt_devs):
        dev = topo.devices.get(key)
        if dev is None:
            continue
        x, y = pos.get(key, (100, 100))
        ids[key] = xb.node(parent, dev.label, SWITCH_STYLE, x, y)
    ext_ips = sorted({a.b_external for a in routing_adjs if a.b_external})
    for j, ip in enumerate(ext_ips):
        ids[f"ext:{ip}"] = xb.node(
            parent, f"{ip}\n(external peer)", EXTERNAL_STYLE,
            200 + (j % 4) * (NODE_W + 60),
            80 + (j // 4) * (NODE_H + 40))
    # Group internal adjacencies (both ends in inventory) by protocol
    # domain — an OSPF area or an iBGP AS. Domains spanning 3+ devices
    # render as a hub with one spoke per member instead of a pairwise
    # mesh (an N-member iBGP mesh is N spokes, not N*(N-1)/2 edges).
    HUB_MIN_MEMBERS = 3
    domains: dict[tuple, list[RoutingAdj]] = {}
    direct: list[RoutingAdj] = []
    unhealthy: list[RoutingAdj] = []
    for adj in routing_adjs:
        if adj.b_key and (adj.protocol == "ospf"
                          or adj.detail.startswith("iBGP")):
            key = (adj.protocol, adj.vrf, adj.detail)
            domains.setdefault(key, []).append(adj)
        else:
            direct.append(adj)
    for (proto, vrf, det), dom_adjs in sorted(domains.items()):
        members = {m for a in dom_adjs for m in (a.a_key, a.b_key)
                   if m in ids}
        if len(members) < HUB_MIN_MEMBERS:
            direct.extend(dom_adjs)
            continue
        # A hub hides per-adjacency state, so a neighbour that is not
        # up must not vanish into it: draw those pairwise as well.
        unhealthy.extend(a for a in dom_adjs if not _adj_healthy(a))
        label = det if proto == "bgp" else f"OSPF {det}"
        if vrf != "default":
            label += f"\nvrf {vrf}"
        xs = [pos[m][0] for m in members if m in pos]
        ys = [pos[m][1] for m in members if m in pos]
        hub_style = OSPF_HUB_STYLE if proto == "ospf" else BGP_HUB_STYLE
        spoke_style = (OSPF_EDGE_STYLE if proto == "ospf"
                       else BGP_EDGE_STYLE)
        hub = xb.node(parent, label, hub_style,
                      sum(xs) / len(xs), sum(ys) / len(ys), w=170, h=55)
        for m in sorted(members):
            xb.edge(parent, "", spoke_style, ids[m], hub)
    for adj in direct:
        src = ids.get(adj.a_key)
        dst = ids.get(adj.b_key or f"ext:{adj.b_external}")
        if not (src and dst):
            continue
        style = (OSPF_EDGE_STYLE if adj.protocol == "ospf"
                 else BGP_EDGE_STYLE)
        wp = (_bow(pos, adj.a_key, adj.b_key, bow_offset)
              if adj.b_key else None)
        xb.edge(parent, adj.label, style, src, dst, waypoint=wp)
    for adj in unhealthy:
        src, dst = ids.get(adj.a_key), ids.get(adj.b_key)
        if src and dst:
            xb.edge(parent, adj.label, ADJ_DOWN_EDGE_STYLE, src, dst,
                    waypoint=_bow(pos, adj.a_key, adj.b_key,
                                  bow_offset or 45.0))


BLOCK_NODE_STYLE = (
    "rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;"
    "fontFamily=Helvetica;fontSize=11;align=center;strokeWidth=2;"
)
SPLIT_MIN_SWITCHES = 16


def _sub_topology(topo: Topology, keys: set) -> Topology:
    sub = Topology()
    for k in sorted(keys):
        dev = topo.devices.get(k)
        if dev:
            sub.upsert_device(Device(**{f: getattr(dev, f)
                                        for f in Device.__dataclass_fields__}))
    for e in topo.edges.values():
        if e.a_key in keys and e.b_key in keys:
            sub.add_edge(Edge(**vars(e)))
    return sub


def _scope_of_pair(info: "ScopeInfo", a: str, b: str) -> tuple:
    """Classify an (a, b) relation: ('core',), ('coreagg',) or
    ('block', bid). Endpoints (non-switch) inherit their peer."""
    ta, tb = info.tier.get(a), info.tier.get(b)
    if ta is None and tb is None:
        return ("coreagg",)
    if ta is None:
        a, ta = b, tb
    if tb is None:
        tb = ta
        b = a
    if ta == 0 and tb == 0:
        return ("core",)
    if 0 in (ta, tb):
        return ("coreagg",)
    ba, bb = info.block.get(a), info.block.get(b)
    if ba is not None and ba == bb:
        return ("block", ba)
    return ("coreagg",)


def _csv_interface_name(name: str) -> str:
    """Prefix bare port numbers so spreadsheets don't parse 1/1/1 as a
    date."""
    if re.fullmatch(r"\d+(/\d+)*", name):
        return f"Interface {name}"
    return name


def _ipam_rows(details: dict[str, "PortInfo"]) -> list[tuple]:
    rows = []
    for p in details.values():
        for addr in p.ip4:
            vlan = str(p.svi_vlan) if p.svi_vlan is not None else ""
            ag = p.active_gateway or "N/A"
            rows.append((p.svi_vlan if p.svi_vlan is not None else 10**6,
                         p.name, vlan, addr, p.vrf, ag))
    rows.sort()
    return [r[1:] for r in rows]


def write_ipam_csv(path: str, topo: Topology,
                   port_details: dict[str, dict[str, "PortInfo"]]) -> int:
    """Flat addressing inventory: one row per configured address.

    Columns: hostname, interface, vlan, ip, prefix, network, vrf,
    active_gateway. The network column makes 'everything on this subnet' a single
    filter in Excel or a grep on the CLI.
    """
    count = 0
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["hostname", "interface", "vlan", "ip", "prefix",
                    "network", "vrf", "active_gateway"])
        for key in sorted(port_details,
                          key=lambda k: (topo.devices[k].hostname or k)
                          if k in topo.devices else k):
            dev = topo.devices.get(key)
            if dev is None:
                continue
            for ifname, vlan, addr, vrf, ag in _ipam_rows(
                    port_details[key]):
                try:
                    iface = ipaddress.ip_interface(addr)
                    ip_s = str(iface.ip)
                    prefix = str(iface.network.prefixlen)
                    network = str(iface.network)
                except ValueError:
                    ip_s, prefix, network = addr, "", ""
                w.writerow([dev.hostname or key,
                            _csv_interface_name(ifname), vlan, ip_s,
                            prefix, network, vrf, ag])
                count += 1
    return count


def build_split_pages(topo: Topology, info: "ScopeInfo",
                      l2_edges, l3_segments, routing_adjs, vsx_pairs,
                      detail_small: bool = True, layout: str = "tiered"):
    """Area-grouped tabs: Overview, Core L3, then per area (Core-Agg
    first, then each block) L1 / L2 / L3 / IPAM adjacent, so reviewing
    walks one area completely before the next."""
    pages = []
    l2_edges = l2_edges or []
    l3_segments = l3_segments or []
    routing_adjs = routing_adjs or []
    blocks = sorted(info.block_label)
    members: dict[int, set] = {b: set() for b in blocks}
    for k, b in info.block.items():
        members[b].add(k)
    ep_block: dict[str, int] = {}
    for e in topo.edges.values():
        for k, other in ((e.a_key, e.b_key), (e.b_key, e.a_key)):
            if k not in info.tier and other in info.block:
                ep_block[k] = info.block[other]
    core = set(info.core_keys)
    aggs = {k for k, t in info.tier.items() if t == 1}

    def lay(sub):
        # Pin the estate-wide core on every sub-page. Re-detecting it per
        # page ties core with agg on a single-block sub-graph (both end
        # up in the top row) and would ignore --core / --layout.
        return _layout(sub, vsx_pairs, layout, sorted(core))

    def l2_scope(e):
        return _scope_of_pair(info, e.a_key, e.b_key)

    def seg_scope(seg):
        mk = list(seg.members)
        if len(mk) == 1:
            k = mk[0]
            if k in core:
                return ("core",)
            b = info.block.get(k)
            return ("block", b) if b is not None else ("coreagg",)
        scopes = {_scope_of_pair(info, a, b)
                  for a in mk for b in mk if a < b}
        return scopes.pop() if len(scopes) == 1 else ("coreagg",)

    def adj_scope(a):
        if a.b_external:
            k = a.a_key
            if k in core:
                return ("core",)
            b = info.block.get(k)
            return ("block", b) if b is not None else ("coreagg",)
        return _scope_of_pair(info, a.a_key, a.b_key)

    # ---- Overview ------------------------------------------------------
    def render_overview(xb):
        sub = _sub_topology(topo, core)
        pos = lay(sub)
        ids = {}
        _vsx_boxes(xb, "1", pos, vsx_pairs, core)
        for k in sorted(core):
            x, y = pos[k]
            ids[k] = xb.node("1", topo.devices[k].label, SWITCH_STYLE, x, y)
        for e in sub.edges.values():
            xb.edge("1", "", EDGE_STYLE, ids[e.a_key], ids[e.b_key],
                    src_label=e.a_port, dst_label=e.b_port)
        cy = max((p[1] for p in pos.values()), default=150) + TIER_H
        cx0 = min((p[0] for p in pos.values()), default=200) - UNIT_W
        counts: dict[tuple, int] = {}
        for e in topo.edges.values():
            for a, b in ((e.a_key, e.b_key), (e.b_key, e.a_key)):
                if a in core and info.block.get(b) is not None:
                    counts[(a, info.block[b])] = counts.get(
                        (a, info.block[b]), 0) + 1
        for j, bid in enumerate(blocks):
            n_edge = sum(1 for k in members[bid]
                         if info.tier.get(k, 0) >= 2)
            n_agg = sum(1 for k in members[bid]
                        if info.tier.get(k) == 1)
            label = (f"{info.block_label[bid]}"
                     f"\n{n_agg} agg / {n_edge} access")
            bx = cx0 + (j + 1) * (UNIT_W * 1.6)
            nid = xb.node("1", label, BLOCK_NODE_STYLE, bx, cy,
                          w=NODE_W + 20, h=NODE_H)
            for k in sorted(core):
                c = counts.get((k, bid), 0)
                if c:
                    xb.edge("1", f"{c} links", EDGE_STYLE, ids[k], nid)

    pages.append(("Overview", "page-overview", render_overview))

    # ---- Core L3 (core-only routed relations) --------------------------
    def merge_p2p(segs, adjs):
        """Fold adjacencies into their matching point-to-point subnet:
        one edge labelled 'subnet + OSPF FULL' instead of two parallel
        edges per link. Unmatched adjacencies are returned to draw."""
        merged_segs, leftover = [], list(adjs)
        for s in segs:
            if len(s.members) == 2:
                pair = set(s.members)
                notes = []
                still = []
                for a in leftover:
                    if (a.b_key and {a.a_key, a.b_key} == pair
                            and a.vrf == s.vrf):
                        notes.append(f"{a.protocol.upper()} "
                                     f"{a.state}".strip())
                    else:
                        still.append(a)
                leftover = still
                if notes:
                    s = L3Segment(vrf=s.vrf, network=s.network,
                                  members=dict(s.members),
                                  proto_note=" · ".join(sorted(set(notes))))
            merged_segs.append(s)
        return merged_segs, leftover

    def routed_page(name, pid, segs, adjs):
        segs, adjs = merge_p2p(segs, adjs)
        if not segs and not adjs:
            return
        def render(xb, segs=segs, adjs=adjs):
            keys = set()
            for s in segs:
                keys |= set(s.members)
            for a in adjs:
                keys.add(a.a_key)
                if a.b_key:
                    keys.add(a.b_key)
            sub = _sub_topology(topo, keys)
            pos = lay(sub)
            if segs:
                _render_l3(xb, "1", sub, pos, segs, detail=detail_small)
            if adjs:
                _render_routing(xb, "1", sub, pos, adjs, bow_offset=45.0)
        pages.append((name, pid, render))

    routed_page("Core L3", "page-l3-core",
                [s for s in l3_segments if seg_scope(s) == ("core",)],
                [a for a in routing_adjs if adj_scope(a) == ("core",)])

    # ---- Area page sets: Core-Agg first, then each block ---------------
    def l2_page(name, pid, edges):
        if not edges:
            return
        def render(xb, edges=edges):
            keys = {e.a_key for e in edges} | {e.b_key for e in edges}
            sub = _sub_topology(topo, keys)
            pos = lay(sub)
            _render_l2(xb, "1", sub, pos, edges, vsx_pairs,
                       detail=detail_small)
        pages.append((name, pid, render))

    # Core-Agg area: full core<->distribution cabling as its own L1.
    def render_coreagg_l1(xb):
        keys = core | aggs
        sub = _sub_topology(topo, keys)
        pos = lay(sub)
        _render_physical(xb, "1", sub, pos, vsx_pairs,
                         detail=detail_small)
    pages.append(("Core-Agg L1", "page-l1-coreagg", render_coreagg_l1))
    l2_page("Core-Agg L2", "page-l2-coreagg",
            [e for e in l2_edges if l2_scope(e)[0] in ("core", "coreagg")])
    routed_page("Core-Agg L3", "page-l3-coreagg",
                [s for s in l3_segments if seg_scope(s) == ("coreagg",)],
                [a for a in routing_adjs if adj_scope(a) == ("coreagg",)])

    for bid in blocks:
        blk = info.block_label[bid]
        keys = members[bid] | core | {k for k, b in ep_block.items()
                                      if b == bid}
        sub = _sub_topology(topo, keys)

        def render_phys(xb, sub=sub):
            pos = lay(sub)
            _render_physical(xb, "1", sub, pos, vsx_pairs,
                             detail=detail_small)
        pages.append((f"{blk} L1", f"page-l1-b{bid}", render_phys))
        l2_page(f"{blk} L2", f"page-l2-b{bid}",
                [e for e in l2_edges if l2_scope(e) == ("block", bid)])
        routed_page(f"{blk} L3", f"page-l3-b{bid}",
                    [s for s in l3_segments
                     if seg_scope(s) == ("block", bid)],
                    [a for a in routing_adjs
                     if adj_scope(a) == ("block", bid)])
    return pages


_GRAPH_MODEL = """    <mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1"
                  tooltips="1" connect="1" arrows="1" fold="1" page="1"
                  pageScale="1" pageWidth="1600" pageHeight="1200" math="0" shadow="0">
      <root>
        <mxCell id="0"/>
        {body}
      </root>
    </mxGraphModel>"""


def _mxfile(pages: list[tuple[str, str, str]]) -> str:
    """Wrap [(name, page_id, cells_body), ...] as a draw.io file."""
    diagrams = "\n".join(
        f'  <diagram name="{_XmlBuilder._esc(name)}" id="{page_id}">\n'
        + _GRAPH_MODEL.format(body=body)
        + "\n  </diagram>"
        for name, page_id, body in pages)
    return (f'<mxfile host="lldp_mapper" type="device">\n'
            f'{diagrams}\n</mxfile>\n')


def to_drawio_xml(topo: Topology,
                  l2_edges: list[L2Edge] | None = None,
                  l3_segments: list[L3Segment] | None = None,
                  routing_adjs: list[RoutingAdj] | None = None,
                  vsx_pairs: list[tuple[str, str]] | None = None,
                  layered: bool = False,
                  layout: str = "tiered",
                  core_hints: list[str] | None = None,
                  force_detail: bool = False,
                  split: str = "auto") -> str:
    """Emit a draw.io file with one view per PAGE (default) or as
    toggleable layers on a single page (layered=True).

    Pages keep each view on its own clean canvas — tabs along the
    bottom in draw.io — with identical node positions, so flipping
    tabs reads like toggling layers without any overlap. Layered mode
    overlays all views on one page (with per-layer edge bowing) for
    side-by-side comparison, at the cost of visual density.
    """
    pos = _layout(topo, vsx_pairs, layout, core_hints)
    n_switches = sum(1 for d in topo.devices.values() if d.is_switch)
    detail = force_detail or n_switches <= DETAIL_LABEL_MAX_SWITCHES
    if not detail:
        log.info("%d switches > %d: interface labels moved to hover "
                 "tooltips (force with --detail-labels)",
                 n_switches, DETAIL_LABEL_MAX_SWITCHES)

    if layered:
        xb = _XmlBuilder()
        xb.layer("lyr_phys", "1 - Physical (LLDP)", visible=True)
        _render_physical(xb, "lyr_phys", topo, pos, vsx_pairs, detail)
        if l2_edges:
            xb.layer("lyr_l2", "2 - Layer 2 (LAGs / VLANs)", visible=False)
            _render_l2(xb, "lyr_l2", topo, pos, l2_edges, vsx_pairs,
                       bow_offset=30.0, detail=detail)
        if l3_segments:
            xb.layer("lyr_l3", "3 - Layer 3 (subnets / VRFs)",
                     visible=False)
            _render_l3(xb, "lyr_l3", topo, pos, l3_segments,
                       bow_offset=-30.0, detail=detail)
        if routing_adjs:
            xb.layer("lyr_rtg", "4 - Routing (OSPF / BGP)", visible=False)
            _render_routing(xb, "lyr_rtg", topo, pos, routing_adjs,
                            bow_offset=60.0)
        body = "\n        ".join(xb.cells)
        pages = [("Topology", "lldp-topology", body)]
    else:
        info = classify_scopes(topo, vsx_pairs, core_hints)
        do_split = (split == "always"
                    or (split == "auto"
                        and n_switches >= SPLIT_MIN_SWITCHES
                        and info.splittable()))
        pages = []

        def page(name, page_id, render):
            xb = _XmlBuilder()
            xb.cells.append('<mxCell id="1" parent="0"/>')
            render(xb)
            pages.append((name, page_id,
                          "\n        ".join(xb.cells)))

        if do_split:
            log.info("area split: %d blocks (%s) — per-area pages "
                     "(disable with --split never)",
                     len(info.block_label),
                     ", ".join(info.block_label.values()))
            for name, pid, render in build_split_pages(
                    topo, info, l2_edges, l3_segments, routing_adjs,
                    vsx_pairs, detail_small=True, layout=layout):
                page(name, pid, render)
            return _mxfile(pages)

        page("Physical", "page-phys",
             lambda xb: _render_physical(xb, "1", topo, pos, vsx_pairs,
                                         detail))
        if l2_edges:
            page("Layer 2", "page-l2",
                 lambda xb: _render_l2(xb, "1", topo, pos, l2_edges,
                                       vsx_pairs, detail=detail))
        if l3_segments:
            page("Layer 3", "page-l3",
                 lambda xb: _render_l3(xb, "1", topo, pos, l3_segments,
                                       detail=detail))
        if routing_adjs:
            page("Routing", "page-rtg",
                 lambda xb: _render_routing(xb, "1", topo, pos,
                                            routing_adjs))

    return _mxfile(pages)


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
            (diff.added_links, DIFF_ADDED_EDGE, "added"),
            (diff.removed_links, DIFF_REMOVED_EDGE, "removed")):
        for e in edges:
            src, dst = ids.get(e.a_key), ids.get(e.b_key)
            if src and dst:
                xb.edge("lyr_diff", prefix, style, src, dst,
                        src_label=e.a_port, dst_label=e.b_port)

    return _mxfile([("Topology diff", "lldp-diff",
                     "\n        ".join(xb.cells))])


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
    scan.add_argument("subnet", nargs="+",
                      help="one or more CIDRs to scan, e.g. "
                           "10.20.30.0/24 10.40.0.0/22")
    scan.add_argument("-u", "--username", action="append", default=[],
                      help="username to try; repeat for multiple accounts "
                           "(tried in order per switch, prompted for each "
                           "password)")
    scan.add_argument("--creds", metavar="FILE",
                      help="JSON file: [{\"username\": ..., \"password\": "
                           "...}, ...] tried in order per switch (before "
                           "any -u accounts)")
    scan.add_argument("-o", "--output", default="topology.drawio",
                      help="draw.io output file (default: topology.drawio)")
    scan.add_argument("--json", metavar="FILE", default=None,
                      help="JSON inventory path (default: derived from -o, "
                           "e.g. topology.json). Needed for diff mode.")
    scan.add_argument("--no-json", action="store_true",
                      help="skip writing the JSON inventory")
    scan.add_argument("--ipam", metavar="FILE",
                      help="IPAM CSV path (default: ip-addressing.csv "
                           "alongside the -o output)")
    scan.add_argument("--no-ipam", action="store_true",
                      help="skip writing the IPAM CSV")
    scan.add_argument("--api-version", default=DEFAULT_API_VERSION,
                      help="'auto' negotiates the latest version via GET "
                           "/rest (v10.16 on 10.16 firmware); or pin one, "
                           "e.g. v10.04 (default: auto)")
    scan.add_argument("--all-subnets", action="store_true",
                      help="include subnets attached to only one switch "
                           "(SVIs, uplink /30s) as leaf nodes on the L3 "
                           "page — needed for single-switch/stack estates")
    scan.add_argument("--split", choices=["auto", "always", "never"],
                      default="auto",
                      help="area-split pages (Overview + per-block Physical"
                           "/L2/Routed): auto engages on estates of %d+ "
                           "switches with 2+ distribution blocks"
                           % 16)
    scan.add_argument("--detail-labels", action="store_true",
                      help="always print interface labels at edge ends; "
                           "by default estates over %d switches move them "
                           "to hover tooltips" % 15)
    scan.add_argument("--layout", choices=["tiered", "circle"],
                      default="tiered",
                      help="tiered (core top, hierarchy below; default) "
                           "or the original circle")
    scan.add_argument("--core", action="append", default=[],
                      metavar="HOST",
                      help="pin a switch (hostname or IP) to the top tier; "
                           "repeatable — overrides auto core detection")
    scan.add_argument("--layered", action="store_true",
                      help="single page with toggleable layers instead of "
                           "one page per view")
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


def gather_credentials(args) -> list[tuple[str, str]]:
    """Assemble the ordered credential list from --creds and -u.

    File entries come first, then CLI usernames. A single -u with
    AOSCX_PASSWORD set keeps the original non-interactive behaviour;
    otherwise each CLI username is prompted for its password.
    """
    creds: list[tuple[str, str]] = []
    if args.creds:
        try:
            with open(args.creds) as f:
                entries = json.load(f)
        except (OSError, ValueError) as exc:
            log.error("cannot read credentials file %s: %s",
                      args.creds, exc)
            return []
        mode = os.stat(args.creds).st_mode & 0o077
        if mode:
            log.warning("%s is readable by group/other — consider "
                        "chmod 600", args.creds)
        for e in entries if isinstance(entries, list) else []:
            if isinstance(e, dict) and e.get("username"):
                creds.append((str(e["username"]),
                              str(e.get("password", ""))))
    env_pw = os.environ.get("AOSCX_PASSWORD")
    for i, user in enumerate(args.username):
        if env_pw and len(args.username) == 1 and not args.creds:
            creds.append((user, env_pw))
        else:
            creds.append((user, getpass.getpass(
                f"Password for {user}: ")))
    return creds


def dedupe_polled(polled: list[PollResult]) -> list[PollResult]:
    """Drop duplicate polls of the same switch (seen via multiple IPs
    when scanned ranges cover both its mgmt and routed interfaces),
    keyed by chassis MAC. First result wins."""
    seen: dict[str, str] = {}
    out: list[PollResult] = []
    for pr in polled:
        key = pr.device.key
        if key in seen:
            log.info("%s: same switch already polled via %s — skipping "
                     "duplicate", pr.device.mgmt_ip, seen[key])
            continue
        seen[key] = pr.device.mgmt_ip
        out.append(pr)
    return out


def run_scan(args) -> int:
    credentials = gather_credentials(args)
    if not credentials:
        log.error("no credentials supplied — use -u and/or --creds")
        return 1

    candidates: list[str] = []
    for cidr in args.subnet:
        candidates.extend(scan_subnet(cidr, workers=args.scan_workers))
    # Dedupe hosts across overlapping ranges, keep stable IP order.
    candidates = sorted(set(candidates), key=ipaddress.ip_address)
    if not candidates:
        log.error("No hosts responding on tcp/443 — nothing to do.")
        return 1

    want_details = not args.physical_only
    want_routing = want_details and not args.no_routing
    polled: list[PollResult] = []
    with cf.ThreadPoolExecutor(max_workers=args.poll_workers) as pool:
        futures = {
            pool.submit(poll_device, ip, credentials,
                        args.api_version, args.verify_ssl,
                        want_details, want_routing): ip
            for ip in candidates
        }
        for fut in cf.as_completed(futures):
            try:
                result = fut.result()
            except Exception:                        # noqa: BLE001
                # One switch with an unexpected response shape must not
                # abort the whole estate.
                log.exception("%s: unexpected error while polling — "
                              "skipping this host", futures[fut])
                continue
            if result:
                polled.append(result)

    # Completion order is arbitrary; sort so the JSON, the diagram and
    # the "first IP wins" dedupe are identical run to run.
    polled.sort(key=lambda pr: ipaddress.ip_address(pr.device.mgmt_ip))
    polled = dedupe_polled(polled)
    if not polled:
        log.error("No AOS-CX switches successfully polled.")
        return 1

    topo = build_topology(polled, include_endpoints=args.include_endpoints)

    details_by_dev = None
    l2_edges, l3_segments, routing_adjs, vsx_pairs = None, None, None, None
    if want_details:
        details_by_dev = {pr.device.key: pr.details for pr in polled}
        l2_edges = build_l2_edges(topo, details_by_dev,
                                  args.include_endpoints)
        l3_segments = build_l3_segments(details_by_dev,
                                        args.all_subnets)
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
                              routing_adjs, vsx_pairs,
                              layered=args.layered,
                              layout=args.layout, core_hints=args.core,
                              force_detail=args.detail_labels,
                              split=args.split))
    log.info("draw.io diagram written to %s (%s)", args.output,
         "layers: View > Layers" if args.layered
         else "one page per view — tabs at the bottom")

    if details_by_dev and not args.no_ipam:
        ipam_path = args.ipam
        if not ipam_path:
            out_dir = os.path.dirname(args.output)
            ipam_path = os.path.join(out_dir, "ip-addressing.csv") \
                if out_dir else "ip-addressing.csv"
        n_rows = write_ipam_csv(ipam_path, topo, details_by_dev)
        if n_rows:
            log.info("IPAM CSV written to %s (%d addresses)",
                     ipam_path, n_rows)
        else:
            os.remove(ipam_path)

    if not args.no_json:
        json_path = args.json
        if not json_path:
            root, _ = os.path.splitext(args.output)
            json_path = f"{root}.json"
        with open(json_path, "w") as f:
            f.write(to_json(topo, routing_adjs, vsx_pairs))
        log.info("JSON inventory written to %s", json_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
