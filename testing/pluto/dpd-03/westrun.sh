: we can transmit in the clear
ping -q -c 8 -n 192.1.2.23
: bring up the tunnel
ipsec auto --up west-east
: use the tunnel
ping -q -c 8 -n 192.1.2.23
: show the tunnel
ipsec eroute
: Let R_U_THERE packets flow
sleep 10
: ==== cut ====
ipsec eroute
: ==== tuc ====
sleep 10
: Create the block
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
sleep 10
: ==== cut ====
ipsec whack --listevents
ipsec eroute
: ==== tuc ====
sleep 10
: DPD should have triggered now
ipsec eroute
# remove the block
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
ping -q -c 8 -n 192.1.2.23
# Tunnel should be back up now
ipsec eroute
echo done
