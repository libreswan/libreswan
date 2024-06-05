ipsec auto --up north-b
ipsec auto --up north-a-dpd
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.22.254
ipsec whack --trafficstatus
#
../../guestbin/ip.sh route add unreachable 192.1.2.23
# sleep 40
sleep 20
sleep 20
ipsec status | grep north-
../../guestbin/ip.sh route del unreachable 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.22.254
# state number should be higher than the previous one
ipsec whack --trafficstatus
echo done
