#!/bin/sh

SYSTEMD=`pkg-config systemd --variable=systemdsystemunitdir`
if [ -z "$SYSTEMD" ]
then
	echo "no systemd found, installing sysv init system"

else
	echo "Installing systemd ipsec.service in $SYSTEMD"
fi

