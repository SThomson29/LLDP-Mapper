# lldp-mapper

Topology mapper for Aruba AOS-CX estates. Point it at one or more
management subnets with credentials and it discovers the switches,
pulls LLDP, interface, VSX, and routing data over the REST API, and
produces three things:

- a multi-page **draw.io diagram** (physical, L2, L3, routing views)
- a **JSON inventory** that can be diffed between runs to catch
  topology drift
- an **`ip-addressing.csv`** — a flat, filterable addressing inventory
  covering every SVI, routed port, and loopback

No SSH scraping and nothing to configure on the switches beyond the
REST API being enabled.

## Requirements

- Python 3.9+ (tested on 3.12) and `requests` (`pip install requests`
  or `pip install -r requirements.txt`)
- AOS-CX 10.04 or later — 10.16 fully supported, and the API version
  is negotiated per switch, so mixed-firmware estates are fine
- One or more accounts with at least operator (read) rights, local or
  TACACS/RADIUS

## Quick start

```bash
export AOSCX_PASSWORD='...'          # or omit to be prompted
python3 lldp_mapper.py scan 10.20.30.0/24
```

That single command writes `topology.drawio`, `topology.json`, and
`ip-addressing.csv`. Add `-u <user>` if the account isn't in your
creds file (see below); `-o` renames the diagram (the JSON follows
its name); `--json`, `--ipam`, `--no-json`, `--no-ipam` relocate or
skip the data files.

Several subnets can be scanned in one run and merge into a single
topology. A switch that answers on more than one scanned range (its
mgmt address plus a routed interface, say) is deduplicated by chassis
MAC, so it appears once:

```bash
python3 lldp_mapper.py scan 10.20.30.0/24 10.40.0.0/22 172.16.8.0/24
```

Open the `.drawio` file in [draw.io](https://app.diagrams.net) or the
desktop app. Each view is a **page** — tabs along the bottom — and all
pages share node positions, so flipping tabs feels like toggling
views. (`--layered` produces the older single-page mode with
toggleable layers instead, useful when you want views overlaid; edges
are bowed per layer there to reduce overprinting.)

## Credentials

Credentials are tried in order, per switch, until one authenticates —
so mixed-credential estates need one run, not several:

```bash
# interactive: prompted per account, nothing written to disk
python3 lldp_mapper.py scan 10.20.30.0/24 -u admin -u svc_net

# scheduled jobs: JSON file, tried before any -u accounts
python3 lldp_mapper.py scan 10.20.30.0/24 --creds /etc/lldp-mapper/creds.json
```

`creds.example.json` shows the format — a JSON list of
`{"username", "password"}` objects, tried top to bottom. Copy it, fill
in real values, `chmod 600` it, and keep it out of git (the shipped
`.gitignore` already does).

Two behaviours worth knowing. Only an authentication rejection
(HTTP 401) advances to the next credential — unreachable hosts abort
immediately, so dead boxes don't accumulate failed logins. And every
wrong credential *is* a failed login on that switch, which counts
against any lockout policy your AAA enforces — order the list
most-likely-first and keep it short. The scan log names the username
that succeeded on each switch. The same username may appear multiple
times with different passwords (useful mid-rotation), and the log then
doubles as a report of which switches still hold the old password.

## The views

**Physical.** One edge per LLDP-discovered cable, with each port
number rendered at its own end of the link, beside the switch it
belongs to. VSX pairs sit side by side inside a dashed container with
their role (primary/secondary) in the label. `--include-endpoints`
adds APs, phones, and servers seen in LLDP as dashed grey leaf nodes.

**Layer 2.** Physical links collapsed into their LAGs, so a dual-cable
VSX ISL is one edge labelled `2x links · trunk 10-12,20 · native 1`
with the LAG names at each end. VLAN config comes from the aggregated
interface and trunk lists are range-compressed. With
`--include-endpoints`, edge ports also appear labelled with their
access VLAN or trunk config — which is what gives a single stack
(no inter-switch links at all) a useful L2 view, and doubles as an
edge-port VLAN audit anywhere else.

**Layer 3.** SVI and routed-port addresses grouped by (VRF, subnet).
Point-to-point subnets are direct edges with interface + IP at each
end; a subnet shared by three or more switches becomes a hub with one
spoke per switch. Loopbacks (/32) are excluded and non-default VRFs
are named. Where a routing adjacency runs over a collected
point-to-point subnet, the two merge into a single edge —
`10.255.1.0/31` plus `OSPF FULL` on one link — which is what keeps
p2p-heavy OSPF designs readable. By default only *shared* subnets
appear (the page shows adjacency); `--all-subnets` also renders
single-attached subnets as leaf nodes, giving a lone switch or stack
a complete L3 picture.

**Routing.** Live OSPF and BGP adjacencies: OSPF orange with area and
state, BGP purple with iBGP/eBGP distinguished by AS numbers and
session state. Peers matched to the inventory by interface/peer IP
(router-id fallback for OSPF); anything unmatched — WAN routers,
firewalls — renders as an amber "external peer" node rather than
disappearing. An OSPF area or iBGP mesh spanning three or more
switches collapses into a protocol hub with one spoke per member
(an 8-switch iBGP full mesh is 8 spokes, not 28 edges).

## Layout

The tiered layout (default) infers the hierarchy from the wiring:
cores are found by iterative minimum-degree peeling — access strips
away first, then aggregation, and whoever survives is the core, which
holds up on dual-homed designs where distance-based detection fails.
VSX partners always land in the same tier. Below the core, switches
cluster into distribution blocks under their own parent pair, with
gaps between blocks and parents aligned directly above their children.
Within a row, order follows the **primary parent's interface numbers**
(the `-01`/`-a` device of a pair): core port 1/1/1's block sits
leftmost, so the drawing matches the patching. The scan log names the
detected core tier; pin it manually with `--core <hostname-or-IP>`
(repeatable) if an unusual topology fools the detection, or use
`--layout circle` for the original radial layout.

## Large estates

Two mechanisms keep big estates readable, both automatic:

**Interface labels → tooltips.** Above 15 switches, per-end port
labels move to hover tooltips (hover any link to see its ports) so
the overview zoom stays clean. `--detail-labels` forces printed
labels back.

**Area-split pages.** At 16+ switches with two or more distribution
blocks, the output splits into per-area tabs, grouped so you review
one area completely before the next:

- **Overview** — cores drawn in full, one summary node per block
  (`agg-1 — 2 agg / 4 access`), uplinks aggregated to counted edges
- **Core L3** — the core pair's own routed relations
- **Core-Agg L1 / L2 / L3** — the full core-to-distribution cabling
  with port detail, interconnect trunks, and interconnect
  subnets/adjacencies
- **per block: `agg-1 L1 / L2 / L3`** and so on — each block's own
  pages, small enough that printed interface labels return

Block names derive from hostname common prefixes (`agg-1a`/`agg-1b`
→ `agg-1`). Control with `--split always|never|auto`. Addressing is
deliberately *not* in the drawing at any size — that's the CSV's job.

## The IP addressing CSV

Every scan that collects interface details writes
`ip-addressing.csv` (next to the diagram; `--ipam FILE` relocates it,
`--no-ipam` skips it). One row per configured address:

```
hostname, interface, vlan, ip, prefix, network, vrf, active_gateway
```

Bare port numbers are written as `Interface 1/1/1` so spreadsheets
don't parse them as dates. `active_gateway` carries the VSX
active-gateway VIP where configured, `N/A` otherwise. The `network`
column is the workhorse: filter on it and you have every device on a
subnet. It opens straight into Excel, greps from a jump host, and
diffs in git next to the JSON inventories — dated filenames give you
address-change history for free.

## Diff mode

Every scan writes a JSON inventory by default; keep them and compare
any two:

```bash
python3 lldp_mapper.py diff last-week.json today.json -o diff.drawio
```

The console lists added/removed devices and links; the optional
diagram shows additions in green, removals in red dashed, unchanged in
grey. Exit codes are automation-friendly — **0** no change, **2**
changes detected, **1** error — so it drops into a scheduled job that
alerts on topology drift, or into pre/post-change validation during
migrations.

## Options

| Flag | Default | Notes |
|---|---|---|
| `-u, --username` | — | repeatable; each prompted for a password (single `-u` + `AOSCX_PASSWORD` stays non-interactive) |
| `--creds FILE` | — | JSON credential list, tried before `-u` accounts |
| `-o, --output` | `topology.drawio` | diagram path; the JSON inventory follows its name |
| `--json FILE` / `--no-json` | derived / off | JSON inventory path / skip it (needed for diff) |
| `--ipam FILE` / `--no-ipam` | `ip-addressing.csv` / off | addressing CSV path / skip it |
| `--api-version` | `auto` | negotiate latest via `GET /rest`; pin e.g. `v10.04` to override |
| `--split` | `auto` | area-split pages: auto engages at 16+ switches with 2+ blocks |
| `--detail-labels` | off | force printed port labels above the 15-switch tooltip threshold |
| `--layout` | `tiered` | or `circle` for the original radial layout |
| `--core HOST` | — | pin core switch(es) by hostname or IP; repeatable |
| `--layered` | off | single page with toggleable layers instead of pages |
| `--all-subnets` | off | render single-attached subnets as L3 leaf nodes |
| `--include-endpoints` | off | show devices that respond to LLDP with MAC/Hostname included if available |
| `--physical-only` | off | skip all L2/L3/routing collection |
| `--no-routing` | off | keep L2/L3 but skip the OSPF/BGP walks |
| `--scan-workers` | 64 | concurrent TCP probes during discovery |
| `--poll-workers` | 8 | concurrent switch polls — keep modest (session limits) |
| `--verify-ssl` | off | most switch mgmt certs are self-signed |
| `-v, --verbose` | off | debug logging |

`diff` takes `old.json new.json`, plus `-o` for the diagram and `-v`.

## Operational notes

**REST session limits.** AOS-CX caps concurrent REST sessions per
switch (typically six). The client logs out on every exit path,
including errors, but don't crank `--poll-workers` high or run
multiple instances against the same switches at once — a lingering
lockout means waiting out the idle timeout.

**API versioning.** Each switch's version is negotiated up front via
an unauthenticated `GET /rest`, using the switch-declared latest, per
Aruba's guidance — mixed-firmware estates each get their newest
schema, and 10.15+-only platforms work without configuration. If the
index is unreachable the client falls back to v10.04. The negotiated
version appears per switch in the scan log.

**Collection resilience.** Interface and LLDP data use a single
wildcard query where the firmware supports it, falling back to
per-interface iteration otherwise. An SVI that returns no address in
the filtered response (seen on some firmware when the VLAN is down)
gets one unfiltered re-fetch, and recoveries are logged. Active
gateway is collected by a separate, fully isolated query — if a
firmware rejects that attribute, the only effect is `N/A` in the CSV
column. If a switch somehow yields no interface details at all, a
warning names it rather than letting the gap pass silently. The
OSPF/BGP walk is per-resource and prunes any branch that 404s.

**Scan scope.** Discovery is a TCP probe of 443 across each CIDR;
anything answering gets a REST login attempt. Non-CX devices with
HTTPS management (iLO, printers, firewalls) are skipped with a warning
after the login fails — harmless, but expect log noise on busy
subnets, and remember that failed logins matter on devices with
lockout policies. A single host can be included as a `/32`.

## Tests

Offline suites against synthetic fixtures — no switches needed:

```bash
python3 test_mapper.py            # parsing, dedup, physical output
python3 test_layers.py            # L2 aggregation, L3 segments, layered mode
python3 test_routing_vsx_diff.py  # VSX pairing, OSPF/BGP, diff mode
python3 test_pages.py             # multi-page output, IPAM CSV
python3 test_credentials.py       # credential iteration, multi-subnet dedupe
python3 test_tiered.py            # tiered layout, core detection, --core
python3 test_large_estate.py      # blocks, area split, tooltips, regressions
```

The regression suite includes the field failures this tool has
actually hit: dual-homed core detection, crossed-patching port order,
and the firmware combination that once emptied interface collection.

## Files

```
lldp_mapper.py             the tool (stdlib + requests only)
requirements.txt           just requests (create if you want pip -r)
creds.example.json         credential file template
.gitignore                 keeps output, addressing CSVs, and real creds out
test_*.py                  the seven suites above (+ shared fixtures
                           in test_mapper_common.py)
sample_full.drawio         example multi-page output
sample_layered.drawio      example single-page layered output
sample_diff.drawio         example diff output
```
