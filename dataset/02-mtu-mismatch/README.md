# MTU Mismatch

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
