ipsec auto --up north-east
# change ip to a new one and restart pluto
# PAUL: should no longer matter!
../../guestbin/ip.sh address del 192.1.3.33/24 dev eth1
../../guestbin/ip.sh address add 192.1.3.34/24 dev eth1
../../guestbin/ip.sh route add 0.0.0.0/0 via 192.1.3.254 dev eth1
ipsec whack --impair send_no_delete
ipsec restart
../../guestbin/wait-until-pluto-started
# temp while the test still fails
ipsec whack --impair suppress_retransmits
ipsec auto --add north-east
ipsec auto --up north-east
echo done
