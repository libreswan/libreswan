#!/bin/sh
action=add

for d in {1..190} ; do
	../../guestbin/ip.sh route $action 192.0.2.$d via 192.1.2.254 dev eth1 2>/dev/null
	../../guestbin/ip.sh route $action 192.0.21.$d via 192.1.2.254 dev eth1 2>/dev/null
	../../guestbin/ip.sh route $action 192.0.22.$d via 192.1.2.254 dev eth1 2>/dev/null
done
C=`ip -o route show scope global |wc -l`
echo "Global routes $C"
