ipsec _kernel state
ipsec _kernel policy
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
#check if the address, 192.0.2.1, is removed
../../guestbin/ip.sh address show  dev eth0
echo done
