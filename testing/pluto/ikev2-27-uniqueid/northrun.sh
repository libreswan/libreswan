ipsec whack --impair suppress_retransmits
ipsec auto --up road-eastnet-ikev2
# change ip to a new one and restart pluto
ip addr del 192.1.3.33/24 dev eth1
ip addr add 192.1.3.34/24 dev eth1
ip route add 0.0.0.0/0 via 192.1.3.254 dev eth1
killall -9 pluto
ipsec restart
../../guestbin/wait-until-pluto-started
# temp while the test still fails
ipsec whack --impair suppress_retransmits
ipsec auto --add road-eastnet-ikev2
ipsec auto --up road-eastnet-ikev2
echo done
