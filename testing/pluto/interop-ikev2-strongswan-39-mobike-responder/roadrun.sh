ipsec auto --up road-eastnet
ping -W 1 -q -n -c 2 192.0.2.254
ipsec whack --trafficstatus
# note this end should be 192.1.3.209
ip xfrm state
ip xfrm policy
sleep 15
# remove this end ip next one will take over
ip route show scope global | grep 192.1.3.254 && ip route del default via 192.1.3.254
ip route show scope global | grep 192.1.33.254 || ip route add default via 192.1.33.254
ip addr del 192.1.3.209/24 dev eth0
ip route show scope global
ip addr show scope global
# let libreswan detect change and do a MOBIKE update
sleep 10
# both ends updated MOBIKE ping should work
# note this end should be 192.1.33.222
ipsec whack --trafficstatus
ping -W 1 -q -n -c 4 -I 192.0.3.1 192.0.2.254
ipsec whack --trafficstatus
echo done
