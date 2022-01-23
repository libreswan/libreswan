ipsec auto --up eastnet-westnet-ikev2
../../guestbin/ping-once.sh --up -I 192.1.2.23
setkey -D
setkey -DP
dmesg | grep ipsec
