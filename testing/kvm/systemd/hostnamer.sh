#!/bin/sh

echo hostnamer: determining hostname | tee /dev/console

host()
{
	echo hostnamer: hostname: $1 | tee /dev/console
	hostnamectl set-hostname $1
	exit 0
}

# this will fail for the build domains leaving the default

for mac in $(ip address show | awk '$1 == "link/ether" { print $2 }') ; do
    echo hostnamer: mac: ${mac} | tee /dev/console
    case ${mac} in
    	 #   eth0                 eth1               eth2
	                     12:00:00:de:ad:ba | 12:00:00:32:64:ba ) host nic ;;
	 12:00:00:dc:bc:ff | 12:00:00:64:64:23                     ) host east ;;
	 12:00:00:ab:cd:ff | 12:00:00:64:64:45                     ) host west ;;
	 12:00:00:ab:cd:02                                         ) host road ;;
	 12:00:00:de:cd:49 | 12:00:00:96:96:49                     ) host north ;;
     esac
done

echo hostnamer: hostname unchanged
