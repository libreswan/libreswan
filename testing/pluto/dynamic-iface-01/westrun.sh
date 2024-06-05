ipsec auto --up west-east
../../guestbin/ip.sh address add 192.1.2.66/24 dev eth1
arping -c 1 -U -I eth1 192.1.2.66
ipsec auto --ready
ipsec auto --up float-east #retransmits
../../guestbin/ip.sh address del 192.1.2.66/24 dev eth1
# filter the error, it sometimes changes which network error happens (22 vs 101)
ipsec auto --ready | sed "s/failed in delete notify.*$/failed in delete notify [...]/"
ipsec auto --up west-float #retransmits
# wait for pending cleanups
sleep 30
sleep 30
echo done
