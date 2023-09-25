../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
#check if the address, 192.0.2.1, is removed
ip addr show  dev eth0
echo done
