../../guestbin/ping-once.sh --up 192.0.2.254
# ipsec traffic status must be empty
ipsec trafficstatus
ipsec auto --up north-east
../../guestbin/ping-once.sh --down 192.0.2.254
ipsec trafficstatus
ip -s link show vti0
../../guestbin/route.sh
../../guestbin/xfrmcheck.sh
../../guestbin/route.sh add 192.0.2.0/24 dev vti0
../../guestbin/ping-once.sh --up 192.0.2.254
ip -s link show vti0
ipsec trafficstatus
echo "initdone"
