ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
../../pluto/bin/ipsec-look.sh
# sleep for 30s to run a few liveness cycles
sleep 15
sleep 15
# setting up block
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
# sleeping for timeout
sleep 20
sleep 20
sleep 20
iptables -F
# this msgid should be 2
ipsec auto --down  westnet-eastnet-ipv4-psk-ikev2
