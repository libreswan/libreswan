ipsec auto --route eastnet-westnet-ikev2
setkey -D
setkey -DP
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
