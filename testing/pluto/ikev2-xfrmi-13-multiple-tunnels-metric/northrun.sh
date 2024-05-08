ipsec auto --up north-east-gw
ipsec auto --up north-east-sn
ip link show type xfrm
../../guestbin/ping-once.sh --up -I 192.1.3.33 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.1.3.33 192.0.21.254
ipsec auto --down north-east-sn
../../guestbin/ping-once.sh --up -I 192.1.3.33 192.1.2.23
ipsec auto --down north-east-gw
echo done
