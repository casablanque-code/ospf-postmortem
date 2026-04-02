# Authentication Mismatch

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
