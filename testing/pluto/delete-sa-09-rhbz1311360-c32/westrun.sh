ipsec auto --up west-east
ipsec auto --up westnet-eastnet
# give the EVENT_v1_REPLACE a second to die 
sleep 2
ipsec showstates
ipsec auto --down  west-east
echo done
