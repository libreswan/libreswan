strongswan up road-east
../../guestbin/ping-once.sh --up -I 192.0.3.10 192.0.2.254
strongswan status
# note this end should be 192.1.3.209
../../guestbin/ipsec-kernel-state.sh
ip xfrm policy
sleep 5
# remove this end ip next one will take over
../../guestbin/ip.sh route show scope global | grep 192.1.3.254 && ip route del default via 192.1.3.254
../../guestbin/ip.sh route show scope global | grep 192.1.33.254 || ip route add default via 192.1.33.254
ip addr del 192.1.3.209/24 dev eth0
# let strongswan do a MOBIKE update
sleep 10
# both ends updated MOBIKE ping should work
# note this end should be 192.1.33.222
strongswan status
../../guestbin/ipsec-kernel-state.sh
ip xfrm policy
../../guestbin/ping-once.sh --up -I 192.0.3.10 192.0.2.254
grep "requesting address change using MOBIKE" /tmp/charon.log | sed "s/^.*road/road/"
echo done
