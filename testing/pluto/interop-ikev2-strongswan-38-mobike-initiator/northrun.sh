strongswan up westnet-eastnet-ikev2
ping -W 1 -q -n -c 2 -I 192.0.3.254 192.0.2.254
strongswan status
# note this end is 192.1.3.33
ip xfrm state
ip xfrm policy
sleep 5
# remove this end ip next one will take over
ip addr del 192.1.3.33/24 dev eth1
# let strongswan do a MOBIKE update
sleep 10
# both ends updated MOBIKE ping should work
# note this end should be 192.1.3.34
strongswan status
ping -W 1 -q -n -c 2 -I 192.0.3.254 192.0.2.254
echo done
