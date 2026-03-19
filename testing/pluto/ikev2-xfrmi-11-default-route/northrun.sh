../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
ipsec auto --up north-east
../../guestbin/ping-once.sh --down 192.0.2.254
ipsec trafficstatus
../../guestbin/ip.sh -s link show ipsec2
../../guestbin/ip-route.sh
../../guestbin/ip-route.sh add 192.0.2.0/24 dev ipsec2
../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ip.sh -s link show ipsec2
ipsec trafficstatus
echo "initdone"
