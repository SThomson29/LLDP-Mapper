# lldp-mapper

LLDP-based topology mapper for Aruba AOS-CX estates. Scans a subnet for
switches, pulls LLDP, interface, VSX, and routing data over the AOS-CX
REST API, and emits a multi-layer draw.io diagram plus a JSON inventory
that can be diffed between runs.

No SSH scraping, no per-device config — point it at a management subnet
with credentials and it maps what it finds.

## Requirements

- Python 3.9+ (tested on 3.12)
- `requests` (`pip install requests`)
- AOS-CX 10.04 or later (10.16 fully supported) with the REST API enabled (`https-server rest access-mode read-write` is not required — read-only is sufficient)
- A local account or TACACS/RADIUS account with at least operator rights

## Quick start

```bash
export AOSCX_PASSWORD='...'          # or omit to be prompted
python3 lldp_mapper.py scan 10.20.30.0/24 -u admin \
    -o topology.drawio --json inventory.json
```

Open `topology.drawio` in [draw.io](https://app.diagrams.net) or the
desktop app, then use **View → Layers** to switch between views.
The bare form `python3 lldp_mapper.py 10.20.30.0/24 -u admin` also works
(`scan` is implied).

## What you get

The diagram contains up to four layers, all sharing the same node
positions so devices stay put as you toggle:

**1 — Physical (LLDP)** — visible on open. One edge per discovered
cable, labelled `local-port ↔ remote-port`. VSX pairs are placed side
by side inside a dashed container with their role (primary/secondary)
in the node label. Add `--include-endpoints` to also show APs, phones,
and servers seen in LLDP as dashed grey leaf nodes.

**2 — Layer 2 (LAGs / VLANs)** — physical links collapsed into their
LAGs using each switch's LAG member lists, so a dual-cable VSX ISL
renders as one edge labelled `lag256 ↔ lag256 · 2x links · trunk
10-12,20 · native 1`. VLAN config is read from the aggregated interface
and trunk lists are range-compressed.

**3 — Layer 3 (subnets / VRFs)** — SVI and routed-port IPs grouped by
(VRF, subnet). Point-to-point subnets (/31, /30) become direct edges
labelled with both interface IPs; subnets spanning three or more
switches render as a green subnet hub with a spoke per switch.
Loopbacks (/32) are excluded. Non-default VRFs are named in the label.

**4 — Routing (OSPF / BGP)** — live protocol adjacencies. OSPF
neighbours (orange, `area 0.0.0.0 · FULL`) are matched to inventory by
neighbour interface IP with router-id fallback; BGP peers (purple,
iBGP/eBGP distinguished with AS numbers and session state) by peer IP.
Peers that aren't in the scanned inventory — WAN routers, firewalls —
appear as amber "external peer" nodes rather than being dropped.

## Diff mode

Save `--json` inventories from each run, then compare:

```bash
python3 lldp_mapper.py diff last-week.json today.json -o diff.drawio
```

Console output lists added/removed devices and links; the optional
diagram shows additions in green, removals in red dashed, unchanged in
grey. Exit codes are automation-friendly: **0** = no change, **2** =
changes detected, **1** = error, so it drops straight into a scheduled
job that alerts on topology drift, or into pre/post-change validation
during migrations.

## Options

| Flag | Default | Notes |
|---|---|---|
| `-o, --output` | `topology.drawio` | draw.io output path |
| `--json FILE` | off | also write JSON inventory (needed for diff) |
| `--include-endpoints` | off | show non-switch LLDP neighbours |
| `--physical-only` | off | skip L2/L3/routing collection entirely |
| `--no-routing` | off | keep L2/L3 but skip the OSPF/BGP walks |
| `--api-version` | `auto` | negotiates latest via `GET /rest` (v10.16 on 10.16 firmware); pin e.g. `v10.04` to override |
| `--scan-workers` | 64 | concurrent TCP probes during subnet scan |
| `--poll-workers` | 8 | concurrent switch polls — keep modest, see below |
| `--verify-ssl` | off | most switch mgmt certs are self-signed |
| `-v, --verbose` | off | debug logging |

## Operational notes

**REST session limits.** AOS-CX caps concurrent REST sessions per
switch (typically six). The client logs out on every exit path,
including errors, but avoid cranking `--poll-workers` high or running
multiple instances against the same switches simultaneously — a
lingering session lockout means waiting for the idle timeout.

**API versioning.** Each switch's API version is negotiated up front
via an unauthenticated `GET /rest`, using the switch-declared latest
(v10.16 on 10.16 firmware) per Aruba's best-practice guidance — so
mixed-firmware estates each get their newest schema, and platforms
introduced in 10.15+ (which don't publish the old versions) work
without configuration. If the version index is unreachable the client
falls back to v10.04, which all 10.04+ firmware publishes. The
negotiated version is shown per switch in the scan log.

**Firmware compatibility.** LLDP and interface data are fetched with a
single wildcard query (`/system/interfaces/*/...`) where the firmware
supports it, silently falling back to per-interface iteration on older
releases. The OSPF/BGP walk is per-resource and prunes any branch that
404s, so mixed-routing estates are fine.

**Scan scope.** Discovery is a TCP probe of port 443 across the CIDR;
anything answering gets one REST login attempt. Non-CX devices with
HTTPS management (iLO, printers, firewalls) are skipped with a warning
after the login fails — harmless, but expect log noise on busy subnets,
and be mindful of what a failed login means on devices with lockout
policies.

**Layout.** The circular layout is a starting point. For larger
estates, draw.io's Arrange → Layout (e.g. organic or tree) will usually
produce something better; port labels and layers survive re-layout.

## Tests

Offline suites run against synthetic fixtures — no switches needed:

```bash
python3 test_mapper.py            # parsing, dedup, physical XML
python3 test_layers.py            # L2 aggregation, L3 segments, layers
python3 test_routing_vsx_diff.py  # VSX pairing, OSPF/BGP, diff mode
```

The shared fixture (`test_mapper_common.py`) models a VSX core pair
with a dual-cable ISL, LAG uplinks, a CORP-VRF SVI across three
switches, a /31 OSPF link, iBGP between cores, and an external eBGP
peer.

## Files

```
lldp_mapper.py             the tool (stdlib + requests only)
test_mapper.py             base test suite
test_layers.py             L2/L3 layer tests
test_routing_vsx_diff.py   routing / VSX / diff tests
test_mapper_common.py      shared synthetic fixtures
sample_full.drawio         example 4-layer output
sample_diff.drawio         example diff output
```
