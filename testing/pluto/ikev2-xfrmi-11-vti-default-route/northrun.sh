# no ipsec; traffic status must be empty
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus

ipsec up north-east # sanitize-retransmits
../../guestbin/ping-once.sh --down 192.0.2.254
ipsec trafficstatus

../../guestbin/ip.sh -s link show vti0
../../guestbin/ip-route.sh
../../guestbin/xfrmcheck.sh
../../guestbin/ip-route.sh add 192.0.2.0/24 dev vti0
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
../../guestbin/ip.sh -s link show vti0

echo "initdone"
