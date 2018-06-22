ipsec auto --up westnet-eastnet-ikev2
sleep 5
ipsec status |grep STATE_
# rerunning --up should use CREATE_CHILD_SA
ipsec auto --up westnet-eastnet-ikev2
ipsec status |grep STATE_
sleep 45
ipsec status |grep STATE_
echo done
