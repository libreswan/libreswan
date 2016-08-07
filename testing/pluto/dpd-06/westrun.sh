: we can transmit in the clear
ping -q -c 8 -n -I 192.1.2.45 192.1.2.23
: bring up the tunnel
ipsec auto --up west-east
: use the tunnel
ping -q -c 8 -n -I 192.1.2.45 192.1.2.23
: show the tunnel
ipsec whack --trafficstatus
: Let R_U_THERE packets flow
sleep 10
: ==== cut ====
ipsec whack --trafficstatus
: ==== tuc ====
sleep 10
echo Create the block
iptables -I INPUT -s 192.1.2.23/32  -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
sleep 10
sleep 10
: ==== cut ====
echo Tunnel should be gone
ipsec whack --listevents
ipsec whack --trafficstatus
: ==== tuc ====
# remove the block
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
sleep 10
# Tunnel should be back up now
ipsec whack --trafficstatus
echo done
