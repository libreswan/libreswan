ipsec auto --up westnet-eastnet-ikev2 #retransmits
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec _kernel state
ipsec _kernel policy
echo done
