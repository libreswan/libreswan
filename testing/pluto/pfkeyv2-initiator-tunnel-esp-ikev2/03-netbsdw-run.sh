../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec auto --up eastnet-westnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
setkey -D
setkey -DP
dmesg | grep ipsec
