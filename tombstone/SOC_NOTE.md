# SOC Note - Incident `fin-ws-04`

DLP flagged internal data leaving the finance-staff workstation `fin-ws-04` outside business
hours. We pulled one disk image off that machine (`fin-ws-04.img.gz`, ext4). The employee in
question says it was "just normal work, opening files".

By the time the IR team first looked, the easy trails were already clean: `auth.log`
truncated, the systemd journal vacuumed, `~/.bash_history` gone.

Reconstruct what happened that night: who got in, from where, when, and how the data left.
Treat the image as evidence and work on a copy.

SHA256 (`fin-ws-04.img.gz`): `a5cdfe24a2028f227f5196b5604b75b70152af2d1265f4611c0b4a6209898807`
