#!/bin/sh

set -xe

# The Saved kernel is called $(PREFIX)$(PLATFORM).* so that cleaning
# up transmogrify, using `make uninstall`, cleans up the files.

kernel=$(ls /boot/vmlinuz-* | sort -V | tail -1)
cp -vf ${kernel} /pool/${PREFIX}${PLATFORM}.vmlinuz
ramfs=$(ls /boot/initramfs-*.img | sort -V | tail -1)
cp -vf ${ramfs} /pool/${PREFIX}${PLATFORM}.initramfs

# Ensure that the files are globally readable.  Work-around for
# libvirt/761 where the file ownership is flip-flops between ROOT and
# WHOAMI - a u=r,go= file when owned by ROOT isn't accessible by QEMU
# when running as WHOAMI.

chmod go+r  /pool/${PREFIX}${PLATFORM}.vmlinuz
chmod go+r /pool/${PREFIX}${PLATFORM}.initramfs
