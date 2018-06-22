ipsec auto --up road-eastnet
ping -W 1 -q -n -c 2 192.1.2.23
ipsec whack --trafficstatus
# note this end should be 192.1.3.209
ip xfrm state
sleep 5
# remove this end ip next one will take over
ip addr show scope global dev eth0 | grep -v valid_lft
# delete the routes down to simulate WiFi link down.
ip route del default
ip route del 192.1.33.0/24
ifdown eth0
sed -i '/IPADDR/d' /etc/sysconfig/network-scripts/ifcfg-eth0
sed -i '/GATEWAY/d' /etc/sysconfig/network-scripts/ifcfg-eth0
echo "IPADDR=192.1.33.222" >> /etc/sysconfig/network-scripts/ifcfg-eth0
echo "GATEWAY=192.1.33.254" >> /etc/sysconfig/network-scripts/ifcfg-eth0
sleep 2
# the client is still on the dev lo.
# would the traffic leak in plain
ip addr show dev lo
# let libreswan detect change and initiate MOBIKE update
ifup eth0
sleep 10
# ip addr show scope global dev eth0 | grep -v -E '(valid_lft|ether|noqueue)'
ip addr show scope global dev eth0 | grep -v valid_lft
# MOBIKE ping should work
ping -W 8 -q -n -c 8 192.1.2.23
# "ip xfrm" output this end should be 192.1.33.222
echo done
