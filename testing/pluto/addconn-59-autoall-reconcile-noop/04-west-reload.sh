ipsec add --autoall
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):   conn serial: \([^;]*\);.*/\1 \2/p' | sort
ipsec connectionstatus westnet-eastnet | grep ' routing: '
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

ipsec delete corp/1x2
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):   conn serial: \([^;]*\);.*/\1 \2/p' | sort
ipsec add --autoall
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):   conn serial: \([^;]*\);.*/\1 \2/p' | sort
ipsec connectionstatus westnet-eastnet | grep ' routing: '
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
