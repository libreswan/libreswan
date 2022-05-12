ipsec auto --up eastnet-westnet-ikev2
../../guestbin/ping-once.sh --up --6 2001:db8:1:2::23
setkey -D
setkey -DP
dmesg | grep ipsec
