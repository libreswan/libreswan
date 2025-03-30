strongswan up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
strongswan status
# note this end is 192.1.3.33
ipsec _kernel state
ipsec _kernel policy
sleep 5
# remove this end ip next one will take over
../../guestbin/ip.sh address del 192.1.3.33/24 dev eth1
# let strongswan do a MOBIKE update
sleep 10
# both ends updated MOBIKE ping should work
# note this end should be 192.1.3.34
strongswan status
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
echo done
