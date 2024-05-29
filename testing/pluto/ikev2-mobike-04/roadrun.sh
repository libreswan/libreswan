ipsec auto --up road-eastnet
# note this end should be 192.1.3.209
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ping-once.sh --up -I 192.0.3.10 192.0.2.254
ipsec whack --trafficstatus
sleep 5
# remove this end ip next one will take over
../../guestbin/ip-addr-show.sh
../../guestbin/route.sh
../../guestbin/route.sh show scope global | grep 192.1.3.254 && ip route del default via 192.1.3.254
ip addr del 192.1.3.209/24 dev eth0 
# removed address and route
sleep 5
../../guestbin/ip-addr-show.sh
../../guestbin/route.sh
# add new address and route
ip addr show dev eth0 | grep 192.1.33.209 || ip addr add 192.1.33.209/24 dev eth0
../../guestbin/route.sh show scope global | grep 192.1.33.254 || ip route add default via 192.1.33.254
# let libreswan detect change and do a MOBIKE update
sleep 10
../../guestbin/ping-once.sh --up -I 192.0.3.10 192.1.2.23
../../guestbin/ip-addr-show.sh
../../guestbin/route.sh
# MOBIKE ping should work
# note this end should be 192.1.3.209
../../guestbin/ping-once.sh --up -I 192.0.3.10 192.1.2.23
echo done
