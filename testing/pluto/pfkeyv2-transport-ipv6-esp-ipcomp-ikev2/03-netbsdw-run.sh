ipsec auto --up eastnet-westnet-ikev2
setkey -DP
../../guestbin/ping-once.sh --up 2001:db8:1:2::23
setkey -D
../../guestbin/ping-once.sh --medium --up 2001:db8:1:2::23
setkey -D
dmesg | grep ipsec
