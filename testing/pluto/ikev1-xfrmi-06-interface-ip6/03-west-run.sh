ipsec auto --up westnet-eastnet
../../guestbin/ping-once.sh --up -I 2001:db8:0:1::251 2001:db8:0:2::254
../../guestbin/ping-once.sh --up -I 2001:db8:0:1::251 2001:db8:0:2::254
../../guestbin/ping-once.sh --up -I 2001:db8:0:1::251 2001:db8:0:2::254
../../guestbin/ip.sh address show dev ipsec1
echo done
