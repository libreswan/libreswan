# we can transmit in the clear
../../guestbin/ping-once.sh --up 192.1.2.23
# bring up the tunnel
ipsec auto --up west-east
