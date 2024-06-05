ipsec auto --up road-eastnet
# note this end should be 192.1.3.209
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ping-once.sh --up -I 192.0.3.10 192.0.2.254
ipsec whack --trafficstatus
sleep 5
# remove this end ip next one will take over
../../guestbin/ip-addr-show.sh
../../guestbin/ip.sh route
../../guestbin/ip.sh route show scope global | grep 192.1.3.254 && ip route del default via 192.1.3.254
../../guestbin/ip.sh address del 192.1.3.209/24 dev eth0 
# removed address and route
sleep 5
../../guestbin/ip-addr-show.sh
../../guestbin/ip.sh route
# add new address and route
../../guestbin/ip.sh address show dev eth0 | grep 192.1.33.209 || ../../guestbin/ip.sh address add 192.1.33.209/24 dev eth0
../../guestbin/ip.sh route show scope global | grep 192.1.33.254 || ip route add default via 192.1.33.254
# let libreswan detect change and do a MOBIKE update
sleep 10
../../guestbin/ping-once.sh --up -I 192.0.3.10 192.1.2.23
../../guestbin/ip-addr-show.sh
../../guestbin/ip.sh route
# MOBIKE ping should work
# note this end should be 192.1.3.209
../../guestbin/ping-once.sh --up -I 192.0.3.10 192.1.2.23
echo done
