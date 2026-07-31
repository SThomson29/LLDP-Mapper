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
- One or more accounts with at least operator rights (local or TACACS/RADIUS)

## Quick start

```bash
export AOSCX_PASSWORD='...'          # or omit to be prompted
python3 lldp_mapper.py scan 10.20.30.0/24 -u admin
```

Multiple subnets can be scanned in one run — list them all and the
results merge into a single topology, with any switch that answers on
more than one scanned range (mgmt plus a routed interface, say)
deduplicated by chassis MAC:

```bash
python3 lldp_mapper.py scan 10.20.30.0/24 10.40.0.0/22 172.16.8.0/24 -u admin
```

This writes `topology.drawio`, a matching `topology.json` inventory
(used by diff mode), and an `ip-addressing.csv` addressing inventory —
all by default. Use `-o` to rename (the JSON
follows the diagram name), `--json` to place the inventory elsewhere,
or `--no-json` to skip it.

Open `topology.drawio` in [draw.io](https://app.diagrams.net) or the
desktop app. Each view is a **page** — tabs along the bottom of the
canvas — with identical node positions, so flipping tabs reads like
toggling views without any overlap. Pass `--layered` for the older
single-page mode with toggleable layers (View → Layers) if you want
views overlaid for comparison.
The bare form `python3 lldp_mapper.py 10.20.30.0/24 -u admin` also works
(`scan` is implied).

## What you get

The diagram contains up to four views (pages by default, or layers
with `--layered`), all sharing the same node positions so devices stay
put as you switch. In layered mode, edges are additionally bowed per
layer — physical straight, L2 one side, L3 the other, routing further
out — to reduce overprinting when several layers are visible at once.

**1 — Physical (LLDP)** — visible on open. One edge per discovered
cable, with each port number rendered at its own end of the link —
beside the switch it belongs to — so there is no ambiguity about
which port is which. VSX pairs are placed side
by side inside a dashed container with their role (primary/secondary)
in the node label. Add `--include-endpoints` to also show APs, phones,
and servers seen in LLDP as dashed grey leaf nodes — on both the
physical page and the Layer 2 page, where endpoint links are labelled
with the switch-side port's VLAN config (access VLAN or trunk list).
This is also what makes single-switch or single-stack environments
produce a useful Layer 2 page, since they have no inter-switch links.

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
By default the page shows only *shared* subnets (adjacency); add
`--all-subnets` to also render subnets attached to a single switch —
every SVI and routed port as a leaf node — which is what gives a
single-switch or single-stack estate a complete L3 page.

**4 — Routing (OSPF / BGP)** — live protocol adjacencies. OSPF
neighbours (orange, `area 0.0.0.0 · FULL`) are matched to inventory by
neighbour interface IP with router-id fallback; BGP peers (purple,
iBGP/eBGP distinguished with AS numbers and session state) by peer IP.
Peers that aren't in the scanned inventory — WAN routers, firewalls —
appear as amber "external peer" nodes rather than being dropped.

## Multiple credentials

Mixed-credential subnets are supported — credentials are tried in
order per switch until one authenticates:

```bash
# interactive: prompted for each account's password, nothing on disk
python3 lldp_mapper.py scan 10.20.30.0/24 -u admin -u svc_net

# scheduled jobs: JSON file (chmod 600), tried before any -u accounts
python3 lldp_mapper.py scan 10.20.30.0/24 --creds /etc/lldp-mapper/creds.json
```

See `creds.example.json` for the format — a JSON list of
`{"username", "password"}` objects, tried top to bottom. Copy it,
fill in real values, and `chmod 600` the result.

Only an authentication rejection (HTTP 401) moves on to the next
credential; unreachable hosts abort immediately so they don't burn
attempts. Order the list most-likely-first: each wrong credential is a
failed login on that switch, which counts against any account-lockout
policy your AAA enforces. The scan log shows which username succeeded
per switch.

## IPAM CSV

Whenever interface details are collected, every scan also writes a flat
addressing inventory as CSV (default: `ip-addressing.csv` alongside the
diagram; override with `--ipam FILE`, skip with `--no-ipam`). One row per configured address across every SVI, routed
port, and loopback:

```
hostname, mgmt_ip, interface, vlan, ip, prefix, network, vrf
```

It opens directly in Excel and filters/sorts like the IPAM it
effectively is — the `network` column answers "what's on this subnet"
in one filter. Being plain text, it also greps from a terminal and
diffs cleanly in git alongside the JSON inventories, giving you
address-change history for free. Addressing lives here rather than as
tables in the drawing: diagrams do topology, the CSV does addresses.

## Diff mode

Every scan writes a JSON inventory alongside the diagram by default —
keep them (dated filenames help) and compare any two:

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
| `--json FILE` | derived from `-o` | JSON inventory path (needed for diff) |
| `--no-json` | off | skip the JSON inventory |
| `--all-subnets` | off | render single-attached subnets (SVIs, uplink /30s) as leaf nodes on the L3 page |
| `--layered` | off | single page with toggleable layers instead of one page per view |
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

**Scan scope.** Discovery is a TCP probe of port 443 across each CIDR;
anything answering gets one REST login attempt. Non-CX devices with
HTTPS management (iLO, printers, firewalls) are skipped with a warning
after the login fails — harmless, but expect log noise on busy subnets,
and be mindful of what a failed login means on devices with lockout
policies.

**Layout.** The default tiered layout infers the hierarchy from the
topology itself: the core is found by iterative
minimum-degree peeling (access switches strip away first, then
aggregation, leaving the core — robust on dual-homed designs, with VSX
partners always kept together) and forms the top row, and every further tier is one hop down, so a 3-tier campus renders
as core / aggregation / access rows with endpoints hanging below their
switch. Rows are barycentre-ordered to keep access switches under
their own aggregation and minimise crossing links. If auto-detection
picks the wrong core on an unusual topology, pin it with `--core
<hostname-or-IP>` (repeatable); `--layout circle` restores the original
radial layout. Below each tier, switches are
clustered into distribution blocks under their own parent pair, with
gaps between blocks and parents aligned directly above their children.
Port labels and pages survive manual re-arrangement in draw.io.

**Area-split pages (large estates).** On estates of 16+ switches with
two or more distribution blocks, the output splits into per-area tabs
grouped so you review one area completely before the next: **Overview**
(cores plus one summary node per block, aggregated uplink counts),
**Core L3** (core-pair routed relations), then the **Core-Agg** set —
L1 (the full core-to-distribution cabling with port detail), L2, L3
(interconnect subnets and adjacencies), IPAM (core + agg addressing) —
then per block: **agg-1 L1 / L2 / L3 / IPAM** and so on. L3 pages
combine subnets with routing adjacencies, which suits point-to-point
OSPF designs where a global routed view becomes unreadable. Within
every row, switches are ordered by their uplink's parent-side interface
number, so the diagram matches the physical patching. Control with
`--split always|never|auto`.

**Large estates (flat mode).** Above 15 switches, per-end interface labels move to
hover tooltips automatically (hover any link to see its ports); force
printed labels with `--detail-labels`. On the Routing page, OSPF areas
and iBGP meshes spanning three or more switches collapse into a
protocol hub with one spoke per member — an 8-switch iBGP full mesh
renders as 8 spokes instead of 28 pairwise edges. eBGP and external
peerings stay as direct edges.

## Tests

Offline suites run against synthetic fixtures — no switches needed:

```bash
python3 test_mapper.py            # parsing, dedup, physical XML
python3 test_layers.py            # L2 aggregation, L3 segments, layers
python3 test_routing_vsx_diff.py  # VSX pairing, OSPF/BGP, diff mode
python3 test_pages.py             # multi-page output
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
