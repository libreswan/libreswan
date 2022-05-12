../../guestbin/ping-once.sh --down --6 --I 2001:db8:0:1::254 2001:db8:0:2::254
ipsec auto --up eastnet-westnet-ikev2
../../guestbin/ping-once.sh --up --6 --I 2001:db8:0:1::254 2001:db8:0:2::254
setkey -D
setkey -DP
dmesg | grep ipsec
