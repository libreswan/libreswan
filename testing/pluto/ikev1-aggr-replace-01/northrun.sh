ipsec auto --up north-east
# change ip to a new one and restart pluto
# PAUL: should no longer matter!
ip addr del 192.1.3.33/24 dev eth1
ip addr add 192.1.3.34/24 dev eth1
ip route add 0.0.0.0/0 via 192.1.3.254 dev eth1
killall -9 pluto
ipsec restart
/testing/pluto/bin/wait-until-pluto-started
# temp while the test still fails
ipsec whack --impair suppress-retransmits
ipsec auto --add north-east
ipsec auto --up north-east
echo done
