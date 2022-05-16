../../guestbin/ping-once.sh --down -4 -I 192.0.1.254 192.0.2.254
ipsec auto --up eastnet-westnet-ikev2
setkey -DP
../../guestbin/ping-once.sh --up -4 -I 192.0.1.254 192.0.2.254
setkey -D
../../guestbin/ping-once.sh --big --up -4 -I 192.0.1.254 192.0.2.254
setkey -D
dmesg | grep ipsec
