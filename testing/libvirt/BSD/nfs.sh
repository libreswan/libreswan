#!/bin/sh

dir=$(dirname $0 | sed "s:libvirt/BSD::")

set -e
if [ -f /lib/systemd/system/nfs-server.service ]; then
	sudo systemctl start nfs-server > /dev/null
	sudo exportfs -r
	sudo exportfs -o rw,no_root_squash 192.168.234.0/24:$dir
fi
