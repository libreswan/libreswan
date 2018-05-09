# send one packet, which gets eaten by XFRM, so east does not initiate
! ../../pluto/bin/one-ping.sh -I 192.1.3.209 192.1.2.23 # should fail
# wait on OE to establish
../../pluto/bin/wait-for-whack-trafficstatus.sh private-or-clear
# ping should succeed through tunnel
ping -q -w 4 -n -c 2 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
echo done
