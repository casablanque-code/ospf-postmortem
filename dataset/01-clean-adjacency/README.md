# Clean OSPF Adjacency (Baseline)

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
