ipsec auto --up north-west
../../guestbin/ip.sh -s link show ipsec2
../../guestbin/ip.sh route add 192.0.1.0/24 dev ipsec2
../../guestbin/ping-once.sh --up 192.0.1.254
../../guestbin/ip.sh -s link show ipsec2
ipsec trafficstatus
# second connection will fail
ipsec auto --up north-east
../../guestbin/ip.sh -s link show ipsec2
../../guestbin/ip.sh route add 192.0.2.0/24 dev ipsec3
../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ip.sh -s link show ipsec3
ipsec trafficstatus
echo "initdone"
