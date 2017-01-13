ipsec auto --up  west-east
ipsec auto --up  westnet-eastnet
sleep 1
ipsec status |grep STATE
ipsec auto --down  west-east
echo done
