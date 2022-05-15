ipsec auto --up eastnet-westnet-ikev2
setkey -DP
../../guestbin/ping-once.sh --up -6 2001:db8:1:2::23
setkey -D
../../guestbin/ping-once.sh --big --up -6 2001:db8:1:2::23
setkey -D
dmesg | grep ipsec
