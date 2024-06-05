../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
ipsec auto --up north-east
../../guestbin/ping-once.sh --down 192.0.2.254
ipsec trafficstatus
ip -s link show ipsec2
../../guestbin/ip.sh route
../../guestbin/ip.sh route add 192.0.2.0/24 dev ipsec2
../../guestbin/ping-once.sh --up 192.0.2.254
ip -s link show ipsec2
ipsec trafficstatus
echo "initdone"
