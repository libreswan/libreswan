ipsec auto --up west
# route is not installed both letfsubnet=rightsubnet
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
# add route
../../guestbin/ip.sh address add 192.0.1.254/24 dev ipsec1
../../guestbin/ip.sh route add 192.0.2.0/24 dev ipsec1
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ip.sh -s link show ipsec1
echo done
