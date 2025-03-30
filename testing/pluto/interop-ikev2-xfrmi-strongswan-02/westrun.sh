swanctl --initiate --child westnet-eastnet
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec _kernel policy
ipsec _kernel state
../../guestbin/ip.sh link set up dev ipsec0
../../guestbin/ip.sh route add 192.0.2.0/24 dev ipsec0
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
