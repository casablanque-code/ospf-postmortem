# OSPF Post-Mortem

A browser-based OSPF analyzer for network engineers. Drop a PCAP file — get a structured event timeline, full FSM reconstruction, root cause analysis with causal chains, topology graph, and zero data leaving your machine.

Built in Rust compiled to WebAssembly. No server, no backend, no Node.js.

**Live demo: https://ospf-postmortem.casablanque.workers.dev**

---

## The problem this solves

Wireshark shows you packets. It doesn't tell you *why* the adjacency failed.

An OSPF MTU mismatch looks like a hung DBD exchange — no error, no log, just two routers retransmitting Database Description packets forever. A Hello interval mismatch looks like silence. A duplicate Router-ID looks like random LSA churn. None of these are obvious from raw packet rows.

This tool reconstructs what actually happened: which router entered which FSM state, when the state machine stalled, what caused it, and what to do about it.

---

## What it does

### Full FSM Reconstruction

Reconstructs the complete RFC 2328 neighbor state machine from packet evidence:

```
Hello seen             → Init
Neighbor in Hello list → 2-Way
DBD with I-flag        → ExStart
DBD without I-flag     → Exchange
LSU received           → Loading
LSAck received         → Full
```

Every transition is visible in the event timeline. A state machine stuck in ExStart (MTU mismatch) or never reaching 2-Way (Hello mismatch) is immediately obvious.

### Anomaly Detection

| Event | Severity | Confidence | Description |
|---|---|---|---|
| Neighbor Up | Info | — | New router-ID seen |
| FSM Transition | Info | — | State machine step |
| DR Election | Info | — | Designated Router elected |
| Adjacency Formed | Info | — | Full state reached via LSAck |
| Neighbor Timeout | Warning | 60–95% | Dead interval exceeded |
| DR Change | Warning | 50–90% | DR changed mid-operation |
| Hello Mismatch | Warning | 97% | Timer mismatch — adjacency never forms |
| LSA Flood | Warning | 55–85% | Topology instability |
| MTU Mismatch | Critical | 70–99% | DBD exchange stalls in ExStart |
| Duplicate Router-ID | Critical | 99% | LSDB corruption across the area |
| Auth Mismatch | Critical | 95% | Packets silently rejected |

Each detector includes a confidence score with reasoning — how many packets confirm the issue, why the confidence is high or low.

### Root Cause Analysis

Correlates events into primary causes with causal chains:

```
[CRITICAL] MTU Mismatch — DBD exchange cannot complete
Detection Confidence: 99% — 8 DBD packets with mismatched MTU, 7 retransmissions

Causal Chain:
  +0.0s  [context] Neighbor discovered, Hello exchange successful
  +12.5s [CAUSE]   MTU mismatch detected in DBD — 1400 vs 1500
  +13.5s [effect]  Adjacency never reached Full state

Impact:      OSPF stuck in ExStart. Silent failure — no error logged.
Remediation: verify `show interface` MTU on both sides
Action Plan: Fix MTU mismatch — verify `show interface` on both sides
```

### Network Topology Graph

Reconstructs the network topology from Router-LSA data — the same information OSPF routers use to build their routing tables. Rendered as a force-directed SVG graph with link costs.

### Export

Download the full analysis as JSON (machine-readable) or plain-text post-mortem report (for tickets and incident documentation).

---

## How it works

```
PCAP / PCAPng file (drag & drop)
         │
         ▼
   ArrayBuffer (JS)
         │
         ▼
   WASM module (Rust)
   ├── pcap.rs       — legacy PCAP parser (nom), little/big endian
   ├── pcapng.rs     — PCAPng parser (SHB/IDB/EPB/SPB/OPB blocks)
   ├── net.rs        — Ethernet → IP, 802.1Q, 802.1ad (Q-in-Q)
   ├── ospf.rs       — Hello/DBD/LSU/LSR/LSAck + Router-LSA body
   ├── analyzer.rs   — stateful FSM + topology graph + event detection
   └── root_cause.rs — correlation engine, confidence, causal chains
         │
         ▼
   JSON report → JS frontend → timeline + root cause + topology
```

Everything runs in the browser's WASM sandbox. The file never leaves your machine — no upload, no server, no telemetry.

---

## Compared to existing tools

| | OSPF Post-Mortem | Wireshark | CloudShark |
|---|---|---|---|
| Interface | Browser, drag & drop | Desktop app | Web (cloud) |
| Full FSM reconstruction | ✓ Init→Full | ✗ | ✗ |
| Root cause + causal chain | ✓ | ✗ | ✗ |
| Confidence scores | ✓ | ✗ | ✗ |
| Topology graph from LSA | ✓ | ✗ | ✗ |
| Data leaves machine | ✗ Never | ✗ Never | ✓ Uploaded |
| Requires install | ✗ | ✓ | ✗ |

Wireshark is the right tool for deep packet inspection. This tool answers the question that comes after: *what actually happened, and why did OSPF fail?*

---

## Test dataset

Reproducible anomaly scenarios with known packet sequences for each failure mode.

```
dataset/
├── 01-clean-adjacency/      # baseline — 0 anomalies, full Init→Full convergence
├── 02-mtu-mismatch/         # DBD stuck in ExStart, MTU 1500 vs 1400, confidence 99%
├── 03-hello-mismatch/       # hello=10s vs hello=30s, never forms, confidence 97%
├── 04-auth-mismatch/        # MD5 vs None, silent rejection, confidence 95%
├── 05-duplicate-router-id/  # same RID from two IPs, LSDB corruption, confidence 99%
└── 06-neighbor-flapping/    # neighbor up/down cycles, LSA flood
```

Each scenario has a `README.md` with the expected analysis result. Validated against real Cisco IOS captures (2004, 2018, 2019).

To regenerate:
```bash
pip install scapy
python3 generate-dataset.py
```

---

## Deploy locally

### Requirements

- Rust + Cargo — https://rustup.rs
- wasm-pack — https://rustwasm.github.io/wasm-pack/installer
- Python 3

```bash
rustup target add wasm32-unknown-unknown
git clone https://github.com/casablanque-code/ospf-postmortem
cd ospf-postmortem
make build
make serve
# → http://localhost:8888
```

### Makefile

```bash
make check   # cargo check, fast iteration
make build   # wasm-pack → web/pkg/
make serve   # python3 HTTP server on :8888
make dev     # build + serve
make clean   # remove artifacts
```

### Project structure

```
ospf-postmortem/
├── crates/parser/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs          # WASM entry point, format autodetect
│       ├── pcap.rs         # legacy PCAP parser
│       ├── pcapng.rs       # PCAPng parser (all block types)
│       ├── net.rs          # Ethernet/IP, 802.1Q, Q-in-Q
│       ├── ospf.rs         # OSPF parser + Router-LSA body
│       ├── analyzer.rs     # FSM + topology + event detection
│       └── root_cause.rs   # correlation + confidence + remediation
├── web/
│   ├── index.html          # frontend (single file, no framework)
│   └── pkg/                # generated by wasm-pack
├── dataset/                # test captures with known anomalies
├── generate-dataset.py     # dataset generator (scapy)
└── Makefile
```

---

## Limitations

- Ethernet link type only (other link types skipped)
- FSM reconstruction is approximate — inferred from packet evidence
- Large captures (>100MB) may be slow
- HSRP analysis not yet implemented

---

## Roadmap

- [ ] HSRP detection (UDP 1985) — Coup/Resign, rogue active, priority wars
- [ ] Convergence time measurement — seconds from first Hello to Full
- [ ] CLI version (same Rust crate, no WASM)

---

## Changelog

**Current**
- Full FSM: Loading→Full via LSAck tracking
- Topology graph from Router-LSA (force-directed SVG)
- PCAPng support (SHB/IDB/EPB/SPB/OPB)
- 802.1ad Q-in-Q support
- Confidence scores per detector (0–99%)
- Causal chain visualization
- Root cause correlator with action plan
- Export to JSON and plain-text report
- Dataset: 6 reproducible anomaly scenarios
- Validated on real Cisco IOS captures (2004–2019)
- Deployed on Cloudflare Workers

---

## License

MIT
