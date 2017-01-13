ipsec auto --up  west-east
ipsec auto --up  westnet-eastnet
sleep 1
ipsec status |grep STATE
ipsec auto --down  west-east
sleep 1
# Expecting the IKE SA of west-east and the IPsec SA of westnet-eastnet
ipsec status |grep STATE
echo done
