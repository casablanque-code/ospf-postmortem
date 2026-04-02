# Neighbor Flapping

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
