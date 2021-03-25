ipsec auto --up westnet-eastnet-ikev2 #retransmits
../../pluto/bin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
../../pluto/bin/ipsec-look.sh
echo done
