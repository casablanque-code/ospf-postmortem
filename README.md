# OSPF Post-Mortem

A browser-based OSPF analyzer for network engineers. Drop a PCAP file — get a structured event timeline, FSM state reconstruction, root cause analysis with remediation steps, and zero data leaving your machine.

Built in Rust compiled to WebAssembly. No server, no backend, no Node.js.

![OSPF Post-Mortem screenshot](docs/screenshot.png)

**Live demo: https://ospf-postmortem.emergency-radar.workers.dev**

---

## The problem this solves

Wireshark shows you packets. It doesn't tell you *why* the adjacency failed.

An OSPF MTU mismatch looks like a hung DBD exchange — no error, no log, just two routers retransmitting Database Description packets forever. A Hello interval mismatch looks like silence. A duplicate Router-ID looks like random LSA churn. None of these are obvious from raw packet rows.

This tool reconstructs what actually happened: which router entered which FSM state, when the state machine stalled, what caused it, and what to do about it.

---

## What it does

Parses legacy PCAP captures and reconstructs the OSPF event timeline from raw packets. Tracks neighbor state machines across the full capture and correlates events into root causes.

### Detected events

| Event | Severity | Description |
|---|---|---|
| Neighbor Up | Info | New router-ID seen, adjacency starting |
| FSM Transition | Info | State machine step: Init→2-Way→ExStart→Exchange→Loading→Full |
| DR Election | Info | Designated Router elected |
| Adjacency Formed | Info | DBD exchange progressing toward Full |
| Neighbor Timeout | Warning | Dead interval exceeded, neighbor declared DOWN |
| DR Change | Warning | DR changed mid-operation — reconvergence triggered |
| Hello Interval Mismatch | Warning | Mismatched timers — adjacency will never form |
| LSA Flood | Warning | Topology instability, likely a flapping link |
| MTU Mismatch | Critical | DBD exchange stalls in ExStart — silent failure |
| Duplicate Router-ID | Critical | LSDB corruption across the entire area |
| Authentication Mismatch | Critical | Auth type conflict — adjacency silently rejected |

### Root Cause Analysis

Beyond listing events, the tool correlates them into primary causes and secondary effects:

```
[CRITICAL] MTU Mismatch — DBD exchange cannot complete

Impact:      OSPF adjacency stuck in ExStart. Silent failure.
Effects:     → Adjacency never formed
             → Routes from affected neighbor not in RIB
Affected:    2.2.2.2
Remediation: verify `show interface` MTU on both sides

Action Plan:
  1. Fix MTU mismatch — verify `show interface` on both sides
```

### FSM reconstruction

The tool approximates the RFC 2328 neighbor state machine from packet evidence:

```
Hello seen          → Init
Neighbor in Hello   → 2-Way
DBD with I-flag     → ExStart
DBD without I-flag  → Exchange
LSU received        → Loading
LSAck / silence     → Full (inferred)
```

Stalled state machines — e.g. stuck in ExStart due to MTU mismatch — are visible in the timeline.

---

## How it works

```
PCAP file (drag & drop)
       │
       ▼
  ArrayBuffer (JS)
       │
       ▼
  WASM module (Rust)
  ├── pcap.rs       — binary PCAP parser (nom), legacy format
  ├── net.rs        — Ethernet → IP, 802.1Q, 802.1ad (Q-in-Q)
  ├── ospf.rs       — Hello / DBD / LSU / LSR / LSAck parsers
  ├── analyzer.rs   — stateful FSM + event & anomaly detection
  └── root_cause.rs — correlation engine, remediation, action plan
       │
       ▼
  JSON report → JS frontend → timeline + root cause UI
```

Everything runs in the browser's WASM sandbox. The file never leaves your machine.

---

## Compared to existing tools

| | OSPF Post-Mortem | Wireshark | CloudShark |
|---|---|---|---|
| Interface | Browser, drag & drop | Desktop app | Web (cloud) |
| OSPF FSM reconstruction | ✓ | ✗ | ✗ |
| Root cause + remediation | ✓ | ✗ | ✗ |
| Anomaly detection | ✓ Built-in | ✗ Manual | ✗ |
| Data leaves machine | ✗ Never | ✗ Never | ✓ Uploaded |
| Requires install | ✗ | ✓ | ✗ |

---

## Test dataset

The repository includes reproducible OSPF anomaly scenarios with known packet sequences for each failure mode.

```
dataset/
├── 01-clean-adjacency/      # baseline — 0 anomalies, full convergence
├── 02-mtu-mismatch/         # DBD stuck in ExStart, MTU 1500 vs 1400
├── 03-hello-mismatch/       # hello=10s vs hello=30s, never forms
├── 04-auth-mismatch/        # MD5 vs None, silent rejection
├── 05-duplicate-router-id/  # same RID from two IPs, LSDB corruption
└── 06-neighbor-flapping/    # neighbor up/down cycles, LSA flood
```

Each scenario has a `README.md` with the expected analysis result. Use these to verify the tool or as learning material.

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

### Project structure

```
ospf-postmortem/
├── crates/parser/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs          # WASM entry point
│       ├── pcap.rs         # PCAP binary parser
│       ├── net.rs          # Ethernet/IP, 802.1Q, Q-in-Q
│       ├── ospf.rs         # OSPF packet parser (all 5 types)
│       ├── analyzer.rs     # FSM + event detection
│       └── root_cause.rs   # Correlation + remediation
├── web/
│   ├── index.html          # Frontend (single file, no framework)
│   └── pkg/                # Generated by wasm-pack (git-ignored)
├── dataset/                # Test captures with known anomalies
├── generate-dataset.py     # Dataset generator (scapy)
└── Makefile
```

### Makefile

```bash
make check   # cargo check, fast
make build   # wasm-pack → web/pkg/
make serve   # python3 HTTP server on :8888
make dev     # build + serve
make clean   # remove artifacts
```

---

## Limitations

- Legacy PCAP only — PCAPng not yet supported
- Ethernet link type only
- FSM reconstruction is approximate — inferred from packet evidence, not router internals
- Large captures (>100MB) may be slow
- HSRP analysis not yet implemented

---

## Roadmap

- [ ] Topology graph — reconstruct network diagram from Router-LSA data
- [ ] HSRP detection (UDP 1985) — Coup/Resign, rogue active, priority wars
- [ ] PCAPng support
- [ ] FSM Full state via LSAck tracking
- [ ] Convergence time measurement

---

## License

MIT
