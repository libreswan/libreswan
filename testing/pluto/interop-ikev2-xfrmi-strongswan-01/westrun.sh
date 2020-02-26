swanctl --initiate --child westnet-eastnet
ping -w 4 -c 4 -I 192.0.1.254 192.0.2.254
ip xfrm policy
ip xfrm state
ip route del 192.0.2.0/24
ip link set up dev ipsec2
ip route add 192.0.2.0/24 dev ipsec2
ping -w 4 -c 4 -I 192.0.1.254 192.0.2.254
