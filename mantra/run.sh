#!/bin/sh
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"

exec qemu-system-x86_64 \
	-m 128M \
	-kernel "$DIR/bzImage" \
	-initrd "$DIR/rootfs.cpio.gz" \
	-nographic \
	-monitor none \
	-no-reboot \
	-cpu qemu64,+smep \
	-smp 1 \
	-append "console=ttyS0 nokaslr nopti oops=panic panic=-1 quiet loglevel=1"
