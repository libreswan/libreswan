../../guestbin/ping-once.sh --down -6 -I 2001:db8:0:1::254 2001:db8:0:2::254
ipsec auto --up eastnet-westnet-ikev2
setkey -DP
../../guestbin/ping-once.sh --up -6 -I 2001:db8:0:1::254 2001:db8:0:2::254
setkey -D
../../guestbin/ping-once.sh --big --up -6 -I 2001:db8:0:1::254 2001:db8:0:2::254
setkey -D
dmesg | grep ipsec
