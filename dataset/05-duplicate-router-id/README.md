# Duplicate Router-ID

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
