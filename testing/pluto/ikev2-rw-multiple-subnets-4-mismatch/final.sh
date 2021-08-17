# order of conns is not stable, let's just check if we have our 6 tunnels
ipsec trafficstatus | wc -l
../../guestbin/xfrmcheck.sh
../../guestbin/ipsec-look.sh
