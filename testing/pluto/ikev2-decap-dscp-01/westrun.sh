ipsec auto --up xfrm
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec _kernel state | grep dscp
echo done
