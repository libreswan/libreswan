ipsec auto --up northnet-eastnet
ping -n -q -W 1 -c 2 -I 192.0.3.254  192.0.2.254
ipsec whack --trafficstatus
# note this end should be 192.1.3.33
../../guestbin/ipsec-kernel-state.sh
ip xfrm policy
sleep 5
# remove this end ip next one will take over
ip route replace default via 192.1.3.254
ip route replace 192.1.2.0/24 via 192.1.3.254 src 192.1.3.22
ip addr del 192.1.3.33/24 dev eth1
# let libreswan detect change and do a MOBIKE update
sleep 10
# MOBIKE update and ping should work
ping -n -q -W 1 -c 4 -I 192.0.3.254  192.0.2.254
# note this end should be 192.1.3.22
echo done
