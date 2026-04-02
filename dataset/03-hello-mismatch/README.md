# Hello Interval Mismatch

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
