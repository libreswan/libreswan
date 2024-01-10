ipsec auto --up west-east-transport
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ip xfrm state
ipsec whack --trafficstatus
echo done
