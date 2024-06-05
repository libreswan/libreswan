/testing/guestbin/swan-prep --userland strongswan
ip addr add 192.0.200.254/24 dev eth0:1
../../guestbin/ip.sh route add 192.0.100.0/24 via 192.1.2.23  dev eth1
../../guestbin/strongswan-start.sh
echo "initdone"
