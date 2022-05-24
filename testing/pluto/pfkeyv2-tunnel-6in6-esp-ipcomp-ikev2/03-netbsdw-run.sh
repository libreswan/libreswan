../../guestbin/ping-once.sh --down -I 2001:db8:0:1::254 2001:db8:0:2::254
ipsec auto --up eastnet-westnet-ikev2
setkey -DP
../../guestbin/ping-once.sh --up -I 2001:db8:0:1::254 2001:db8:0:2::254
setkey -D
../../guestbin/ping-once.sh --medium --up -I 2001:db8:0:1::254 2001:db8:0:2::254
setkey -D
dmesg | grep ipsec
