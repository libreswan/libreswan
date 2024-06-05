swanctl --initiate --child westnet-eastnet
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ip xfrm policy
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ip.sh link set up dev ipsec2
../../guestbin/ip.sh route add 192.0.2.0/24 dev ipsec2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
