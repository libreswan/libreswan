ipsec auto --up  westnet-eastnet-ikev2

ipsec look

# give east some time, then delete it again 
sleep 3
ipsec auto --down westnet-eastnet-ikev2
sleep 3
ipsec look

echo done
