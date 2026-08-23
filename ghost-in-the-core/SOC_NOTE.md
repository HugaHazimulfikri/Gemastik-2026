# SOC Incident Note - host "aether-sensor-07"

Our EDR flagged a short-lived process (`sensor`) making an outbound TCP connection to
127.0.0.1:9000 before going quiet. By the time an analyst attached, the process was idle
(sleeping). We captured two artifacts:

- `victim.core.gz` - a core dump of the process, taken while it slept.
- `capture.pcap`   - the egress traffic recorded during the incident window.

The process exfiltrated data and then wiped its working buffers. The binary itself was never
written to disk; it lived only in memory. Recover what was taken.

SHA256(victim.core.gz) = 3b5f20913e5ad5977a82e242a5c0e5e0113aa14790fbfba0de9d6e5f62cf0c6e
SHA256(capture.pcap)   = a482649f3abcb411c196b8b270eaa6e6b5939518fe0aecc8ac9e8d33a65cac8e
