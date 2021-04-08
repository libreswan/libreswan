../../guestbin/ping-once.sh --up 192.0.2.254
# ipsec traffic status must be empty
ipsec trafficstatus
ipsec auto --up north-east
ping -n -q -w 4 -c 4 192.0.2.254
ipsec trafficstatus
ip -s link show vti0
ip route
../../guestbin/xfrmcheck.sh
ip route add 192.0.2.0/24 dev vti0
ping -n -q -w 4 -c 4 192.0.2.254
ip -s link show vti0
ipsec trafficstatus
echo "initdone"
