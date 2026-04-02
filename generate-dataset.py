#!/usr/bin/env python3
"""
generate-dataset.py
Генерирует OSPF pcap датасет с аномалиями используя scapy.
Каждый сценарий — реалистичная последовательность пакетов.

Требования: pip install scapy
Запуск:     python3 generate-dataset.py
"""

import os
import struct
import time
from pathlib import Path

try:
    from scapy.all import (
        Ether, IP, Raw, wrpcap,
        conf as scapy_conf
    )
    scapy_conf.verb = 0
except ImportError:
    print("Установи scapy: pip install scapy")
    exit(1)

DATASET = Path(__file__).parent / "dataset"
DATASET.mkdir(exist_ok=True)

# ── OSPF пакет строим вручную (scapy OSPF contrib нестабилен) ─────────────

def ospf_header(router_id: str, area_id: str, msg_type: int,
                auth_type: int = 0, body: bytes = b"") -> bytes:
    """Собирает OSPF common header (24 байта) + body."""
    rid  = ip2b(router_id)
    area = ip2b(area_id)
    pkt_len = 24 + len(body)

    hdr = struct.pack("!BBH", 2, msg_type, pkt_len)  # ver, type, length
    hdr += rid + area
    hdr += struct.pack("!HH", 0, auth_type)           # checksum, auth_type
    hdr += b"\x00" * 8                                # auth data

    # Считаем checksum если auth_type == 0
    if auth_type == 0:
        raw = hdr + body
        cksum = checksum(raw)
        hdr = hdr[:12] + struct.pack("!H", cksum) + hdr[14:]

    return hdr + body

def ip2b(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def hello_body(net_mask: str, hello_int: int, dead_int: int,
               dr: str = "0.0.0.0", bdr: str = "0.0.0.0",
               neighbors: list = None, priority: int = 1) -> bytes:
    """Hello пакет body (RFC 2328 A.3.2)."""
    body = ip2b(net_mask)
    body += struct.pack("!HBBI", hello_int, 0x02, priority, dead_int)
    body += ip2b(dr) + ip2b(bdr)
    for nb in (neighbors or []):
        body += ip2b(nb)
    return body

def dbd_body(mtu: int, flags: int = 0x07, seq: int = 0x100,
             lsa_headers: list = None) -> bytes:
    """Database Description body."""
    body = struct.pack("!HBBi", mtu, 0x02, flags, seq)
    for lsa in (lsa_headers or []):
        body += lsa
    return body

def lsa_header(ls_age: int, ls_type: int, link_state_id: str,
               adv_router: str, seq: int = 0x80000001) -> bytes:
    """LSA header 20 байт."""
    hdr = struct.pack("!HBB", ls_age, 0x02, ls_type)
    hdr += ip2b(link_state_id)
    hdr += ip2b(adv_router)
    hdr += struct.pack("!IHH", seq, 0, 36)  # seq, cksum, length
    return hdr

def lsu_body(lsas: list) -> bytes:
    """Link State Update body."""
    body = struct.pack("!I", len(lsas))
    for lsa in lsas:
        body += lsa
    return body

def make_pkt(src: str, dst: str, router_id: str, area: str,
             msg_type: int, body: bytes, auth_type: int = 0,
             ts: float = 0.0) -> object:
    """Собирает Ether/IP/OSPF scapy пакет."""
    ospf_raw = ospf_header(router_id, area, msg_type, auth_type, body)
    pkt = (
        Ether(src="02:00:00:00:00:01", dst="01:00:5e:00:00:05") /
        IP(src=src, dst=dst, proto=89, ttl=1) /
        Raw(load=ospf_raw)
    )
    pkt.time = ts
    return pkt

# ── Временные константы ────────────────────────────────────────────────────
T0 = 1_700_000_000.0   # базовый timestamp (не важно какой)

def ts(offset: float) -> float:
    return T0 + offset

# ══════════════════════════════════════════════════════════════════════════
# Сценарий 1: Clean adjacency
# ══════════════════════════════════════════════════════════════════════════
def scenario_clean():
    d = DATASET / "01-clean-adjacency"
    d.mkdir(exist_ok=True)
    pkts = []

    # Hello обмен — оба роутера, 5 циклов
    for i in range(5):
        t = ts(i * 10.0)
        # R1 → multicast
        pkts.append(make_pkt(
            "192.168.1.1", "224.0.0.5", "1.1.1.1", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40,
                       dr="192.168.1.1" if i > 0 else "0.0.0.0",
                       neighbors=["2.2.2.2"] if i > 0 else []),
            ts=t
        ))
        # R2 → multicast
        pkts.append(make_pkt(
            "192.168.1.2", "224.0.0.5", "2.2.2.2", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40,
                       dr="192.168.1.1" if i > 0 else "0.0.0.0",
                       bdr="192.168.1.2" if i > 0 else "0.0.0.0",
                       neighbors=["1.1.1.1"] if i > 0 else []),
            ts=t + 1.0
        ))

    # DBD exchange — ExStart
    pkts.append(make_pkt(
        "192.168.1.1", "192.168.1.2", "1.1.1.1", "0.0.0.0", 2,
        dbd_body(1500, flags=0x07, seq=0x100), ts=ts(12.0)
    ))
    pkts.append(make_pkt(
        "192.168.1.2", "192.168.1.1", "2.2.2.2", "0.0.0.0", 2,
        dbd_body(1500, flags=0x07, seq=0x200), ts=ts(12.1)
    ))
    # DBD exchange — Exchange (master отправляет с LSA headers)
    lsa1 = lsa_header(10, 1, "1.1.1.1", "1.1.1.1")
    pkts.append(make_pkt(
        "192.168.1.1", "192.168.1.2", "1.1.1.1", "0.0.0.0", 2,
        dbd_body(1500, flags=0x03, seq=0x101, lsa_headers=[lsa1]),
        ts=ts(12.3)
    ))
    pkts.append(make_pkt(
        "192.168.1.2", "192.168.1.1", "2.2.2.2", "0.0.0.0", 2,
        dbd_body(1500, flags=0x00, seq=0x101),
        ts=ts(12.4)
    ))

    # LSU
    lsa_full = lsa_header(0, 1, "1.1.1.1", "1.1.1.1") + b"\x00" * 16
    pkts.append(make_pkt(
        "192.168.1.1", "224.0.0.5", "1.1.1.1", "0.0.0.0", 4,
        lsu_body([lsa_full]), ts=ts(13.0)
    ))

    # Продолжаем Hello
    for i in range(5, 15):
        t = ts(i * 10.0)
        pkts.append(make_pkt(
            "192.168.1.1", "224.0.0.5", "1.1.1.1", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40,
                       dr="192.168.1.1", bdr="192.168.1.2",
                       neighbors=["2.2.2.2"]), ts=t
        ))
        pkts.append(make_pkt(
            "192.168.1.2", "224.0.0.5", "2.2.2.2", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40,
                       dr="192.168.1.1", bdr="192.168.1.2",
                       neighbors=["1.1.1.1"]), ts=t + 1.0
        ))

    pkts.sort(key=lambda p: p.time)
    wrpcap(str(d / "capture.pcap"), pkts)

    (d / "README.md").write_text("""# Clean OSPF Adjacency (Baseline)

## Setup
- R1: router-id 1.1.1.1, 192.168.1.1/24, hello=10s, dead=40s
- R2: router-id 2.2.2.2, 192.168.1.2/24, hello=10s, dead=40s
- MTU 1500 on both, no authentication

## Expected result
- 0 anomalies
- NeighborDiscovered x2
- DrElection x1
- AdjacencyFormed x1
- Network converged: YES
""")
    print("  ✓ 01-clean-adjacency")

# ══════════════════════════════════════════════════════════════════════════
# Сценарий 2: MTU Mismatch
# ══════════════════════════════════════════════════════════════════════════
def scenario_mtu_mismatch():
    d = DATASET / "02-mtu-mismatch"
    d.mkdir(exist_ok=True)
    pkts = []

    # Hello — проходят нормально (MTU не в Hello)
    for i in range(4):
        t = ts(i * 10.0)
        pkts.append(make_pkt(
            "10.0.1.1", "224.0.0.5", "1.1.1.1", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40,
                       neighbors=["2.2.2.2"] if i > 0 else []), ts=t
        ))
        pkts.append(make_pkt(
            "10.0.1.2", "224.0.0.5", "2.2.2.2", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40,
                       neighbors=["1.1.1.1"] if i > 0 else []), ts=t + 1.0
        ))

    # DBD ExStart — R1 MTU=1500, R2 MTU=1400 → mismatch
    for i in range(8):
        t = ts(12.0 + i * 5.0)
        pkts.append(make_pkt(
            "10.0.1.1", "10.0.1.2", "1.1.1.1", "0.0.0.0", 2,
            dbd_body(1500, flags=0x07, seq=0x100 + i), ts=t
        ))
        pkts.append(make_pkt(
            "10.0.1.2", "10.0.1.1", "2.2.2.2", "0.0.0.0", 2,
            dbd_body(1400, flags=0x07, seq=0x200 + i), ts=t + 0.5
        ))

    # Hello продолжаются пока DBD висит
    for i in range(4, 12):
        t = ts(i * 10.0)
        pkts.append(make_pkt(
            "10.0.1.1", "224.0.0.5", "1.1.1.1", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40, neighbors=["2.2.2.2"]), ts=t
        ))
        pkts.append(make_pkt(
            "10.0.1.2", "224.0.0.5", "2.2.2.2", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40, neighbors=["1.1.1.1"]), ts=t + 1.0
        ))

    pkts.sort(key=lambda p: p.time)
    wrpcap(str(d / "capture.pcap"), pkts)

    (d / "README.md").write_text("""# MTU Mismatch

## Setup
- R1: router-id 1.1.1.1, 10.0.1.1/24, MTU=1500
- R2: router-id 2.2.2.2, 10.0.1.2/24, MTU=1400

## Expected result
- MtuMismatch: CRITICAL
  - router_id: 2.2.2.2, mtu: 1400, expected_mtu: 1500
- Primary cause: MTU Mismatch
- Impact: DBD exchange stuck in ExStart
- Network converged: NO

## What to observe
- Hellos exchanged normally (no MTU in Hello packets)
- DBD packets show different Interface MTU: 1500 vs 1400
- Routers retransmit DBD indefinitely, never reach Exchange state
""")
    print("  ✓ 02-mtu-mismatch")

# ══════════════════════════════════════════════════════════════════════════
# Сценарий 3: Hello interval mismatch
# ══════════════════════════════════════════════════════════════════════════
def scenario_hello_mismatch():
    d = DATASET / "03-hello-mismatch"
    d.mkdir(exist_ok=True)
    pkts = []

    # R1: hello=10s, R2: hello=30s
    # Генерируем 150 секунд трафика
    t = 0.0
    r1_next = 0.0
    r2_next = 0.0

    while t < 150.0:
        if abs(t - r1_next) < 0.1:
            pkts.append(make_pkt(
                "10.0.2.1", "224.0.0.5", "1.1.1.1", "0.0.0.0", 1,
                hello_body("255.255.255.0", 10, 40), ts=ts(t)
            ))
            r1_next += 10.0

        if abs(t - r2_next) < 0.1:
            pkts.append(make_pkt(
                "10.0.2.2", "224.0.0.5", "2.2.2.2", "0.0.0.0", 1,
                hello_body("255.255.255.0", 30, 120), ts=ts(t + 0.5)
            ))
            r2_next += 30.0

        t += 0.1

    pkts.sort(key=lambda p: p.time)
    wrpcap(str(d / "capture.pcap"), pkts)

    (d / "README.md").write_text("""# Hello Interval Mismatch

## Setup
- R1: router-id 1.1.1.1, hello=10s, dead=40s
- R2: router-id 2.2.2.2, hello=30s, dead=120s

## Expected result
- HelloIntervalMismatch: CRITICAL
  - router_a: 1.1.1.1, interval_a: 10
  - router_b: 2.2.2.2, interval_b: 30
- Primary cause: Hello/Dead Timer Mismatch
- Network converged: NO

## What to observe
- Both send Hellos at their own interval
- RFC 2328: mismatched Hello interval → packet silently discarded
- No DBD packets ever appear — stuck in Init
""")
    print("  ✓ 03-hello-mismatch")

# ══════════════════════════════════════════════════════════════════════════
# Сценарий 4: Authentication mismatch
# ══════════════════════════════════════════════════════════════════════════
def scenario_auth_mismatch():
    d = DATASET / "04-auth-mismatch"
    d.mkdir(exist_ok=True)
    pkts = []

    for i in range(10):
        t = ts(i * 10.0)
        # R1 с MD5 (auth_type=2)
        pkts.append(make_pkt(
            "10.0.3.1", "224.0.0.5", "1.1.1.1", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40),
            auth_type=2, ts=t
        ))
        # R2 без auth (auth_type=0)
        pkts.append(make_pkt(
            "10.0.3.2", "224.0.0.5", "2.2.2.2", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40),
            auth_type=0, ts=t + 1.0
        ))

    pkts.sort(key=lambda p: p.time)
    wrpcap(str(d / "capture.pcap"), pkts)

    (d / "README.md").write_text("""# Authentication Mismatch

## Setup
- R1: router-id 1.1.1.1, MD5 authentication (auth_type=2)
- R2: router-id 2.2.2.2, no authentication (auth_type=0)

## Expected result
- AuthMismatch: CRITICAL
  - router_id: 1.1.1.1, auth_type: 2 (MD5)
  - expected_auth_type: 0 (None)
- Primary cause: Authentication Mismatch
- Network converged: NO

## What to observe
- OSPF header auth_type field: 2 vs 0
- Silent failure — packets discarded without error
- No adjacency forms, no DBD exchange
""")
    print("  ✓ 04-auth-mismatch")

# ══════════════════════════════════════════════════════════════════════════
# Сценарий 5: Duplicate Router-ID
# ══════════════════════════════════════════════════════════════════════════
def scenario_duplicate_rid():
    d = DATASET / "05-duplicate-router-id"
    d.mkdir(exist_ok=True)
    pkts = []

    for i in range(10):
        t = ts(i * 10.0)
        # Оба роутера с router-id 1.1.1.1, но разные src IP
        pkts.append(make_pkt(
            "10.0.4.1", "224.0.0.5", "1.1.1.1", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40,
                       neighbors=["1.1.1.1"] if i > 0 else []), ts=t
        ))
        pkts.append(make_pkt(
            "10.0.4.2", "224.0.0.5", "1.1.1.1", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40,
                       neighbors=["1.1.1.1"] if i > 0 else []), ts=t + 1.0
        ))

    # LSU flood — оба шлют конфликтующие Router-LSA с одним RID
    for i in range(5):
        t = ts(15.0 + i * 8.0)
        lsa1 = lsa_header(i * 2, 1, "1.1.1.1", "1.1.1.1", seq=0x80000001 + i)
        lsa1 += b"\x00" * 16
        pkts.append(make_pkt(
            "10.0.4.1", "224.0.0.5", "1.1.1.1", "0.0.0.0", 4,
            lsu_body([lsa1]), ts=t
        ))
        lsa2 = lsa_header(i * 2 + 1, 1, "1.1.1.1", "1.1.1.1", seq=0x80000002 + i)
        lsa2 += b"\x00" * 16
        pkts.append(make_pkt(
            "10.0.4.2", "224.0.0.5", "1.1.1.1", "0.0.0.0", 4,
            lsu_body([lsa2]), ts=t + 0.3
        ))

    pkts.sort(key=lambda p: p.time)
    wrpcap(str(d / "capture.pcap"), pkts)

    (d / "README.md").write_text("""# Duplicate Router-ID

## Setup
- R1: router-id 1.1.1.1, IP 10.0.4.1/24
- R2: router-id 1.1.1.1, IP 10.0.4.2/24  ← SAME RID

## Expected result
- DuplicateRouterId: CRITICAL
  - router_id: 1.1.1.1
  - ip_a: 10.0.4.1, ip_b: 10.0.4.2
- Primary cause: Duplicate Router-ID
- Impact: LSDB corruption across entire area

## What to observe
- Identical Router-ID in OSPF header from two source IPs
- Conflicting Router-LSAs with same advertising router
- LSA wars: each router overwrites the other's LSA
""")
    print("  ✓ 05-duplicate-router-id")

# ══════════════════════════════════════════════════════════════════════════
# Сценарий 6: Neighbor flapping
# ══════════════════════════════════════════════════════════════════════════
def scenario_flapping():
    d = DATASET / "06-neighbor-flapping"
    d.mkdir(exist_ok=True)
    pkts = []

    def hello_pair(t_offset, with_neighbor=True):
        pkts.append(make_pkt(
            "10.0.5.1", "224.0.0.5", "1.1.1.1", "0.0.0.0", 1,
            hello_body("255.255.255.0", 10, 40,
                       dr="10.0.5.1", bdr="10.0.5.2",
                       neighbors=["2.2.2.2"] if with_neighbor else []),
            ts=ts(t_offset)
        ))
        if with_neighbor:
            pkts.append(make_pkt(
                "10.0.5.2", "224.0.0.5", "2.2.2.2", "0.0.0.0", 1,
                hello_body("255.255.255.0", 10, 40,
                           dr="10.0.5.1", bdr="10.0.5.2",
                           neighbors=["1.1.1.1"]),
                ts=ts(t_offset + 1.0)
            ))

    def lsu_burst(t_offset):
        """LSA flood после flap события."""
        for i in range(12):
            lsa = lsa_header(i, 1, "1.1.1.1", "1.1.1.1", seq=0x80000010 + i)
            lsa += b"\x00" * 16
            pkts.append(make_pkt(
                "10.0.5.1", "224.0.0.5", "1.1.1.1", "0.0.0.0", 4,
                lsu_body([lsa]), ts=ts(t_offset + i * 0.3)
            ))

    # Фаза 1: нормальная работа (0-50s)
    for i in range(5):
        hello_pair(i * 10.0)

    # DBD при первой сходимости
    pkts.append(make_pkt(
        "10.0.5.1", "10.0.5.2", "1.1.1.1", "0.0.0.0", 2,
        dbd_body(1500, flags=0x03, seq=0x100), ts=ts(2.0)
    ))

    # Flap 1: R2 исчезает (50-95s) — R1 шлёт Hello без ответа
    for i in range(5):
        hello_pair(50.0 + i * 10.0, with_neighbor=False)

    # R2 появляется снова (95s) — LSU flood
    lsu_burst(95.0)
    for i in range(3):
        hello_pair(95.0 + i * 10.0)

    # Flap 2: R2 исчезает снова (130-175s)
    for i in range(5):
        hello_pair(130.0 + i * 10.0, with_neighbor=False)

    # R2 снова появляется (175s)
    lsu_burst(175.0)
    for i in range(3):
        hello_pair(175.0 + i * 10.0)

    pkts.sort(key=lambda p: p.time)
    wrpcap(str(d / "capture.pcap"), pkts)

    (d / "README.md").write_text("""# Neighbor Flapping

## Setup
- R1: router-id 1.1.1.1, 10.0.5.1/24 (stable)
- R2: router-id 2.2.2.2, 10.0.5.2/24 (flaps twice)

## Timeline
- t=0s:   normal adjacency
- t=50s:  R2 disappears (no more Hellos from 2.2.2.2)
- t=95s:  R2 comes back → LSA flood
- t=130s: R2 disappears again
- t=175s: R2 comes back again → LSA flood

## Expected result
- NeighborFlapping: WARNING
  - router_id: 2.2.2.2, 2 up/down cycles
- LsaFlood: WARNING (x2 bursts)
- Network converged: NO
""")
    print("  ✓ 06-neighbor-flapping")

# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("OSPF Dataset Generator (scapy)")
    print(f"Output: {DATASET}\n")

    scenario_clean()
    scenario_mtu_mismatch()
    scenario_hello_mismatch()
    scenario_auth_mismatch()
    scenario_duplicate_rid()
    scenario_flapping()

    print(f"\nГотово. Файлы:")
    for f in sorted(DATASET.rglob("*.pcap")):
        size = f.stat().st_size
        print(f"  {f.relative_to(DATASET)}  ({size//1024} KB)")
