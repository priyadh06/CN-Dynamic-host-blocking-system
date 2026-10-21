# Comparison of runs

| Run | Mode | Attacker connections accepted | Conns after block | Detect (s) | Block (s) | Legit success % | False positives |
|---|---|---:|---:|---:|---:|---:|---|
| baseline | baseline | 100 | n/a | 4.08 | n/a | 100.0 | none |
| dynamic | dynamic | 14 | 0 | 3.23 | 3.23 | 100.0 | none |

Reduction in attacker connections reaching the server, relative to baseline (100):

- dynamic: 86.0% (compare runs with the same attack rate/duration; the recorded runs had different numbers of attempts)
