ipsec auto --up  west-east
ipsec auto --up  westnet-eastnet
# give the EVENT_SA_REPLACE a second to die 
sleep 2
ipsec status |grep STATE
ipsec auto --down  west-east
echo done
