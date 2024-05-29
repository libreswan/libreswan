ipsec auto --up west
# route is not installed both letfsubnet=rightsubnet
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
# add route
ip addr add 192.0.1.254/24 dev ipsec1
../../guestbin/route.sh add 192.0.2.0/24 dev ipsec1
ping -n -q -w 4 -c 2 -I 192.0.1.254 192.0.2.254
ip -s link show ipsec1
echo done
