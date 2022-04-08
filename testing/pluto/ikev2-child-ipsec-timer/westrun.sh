ipsec auto --up westnet-eastnet-ikev2
sleep 5
ipsec showstates
# rerunning --up should use CREATE_CHILD_SA
ipsec auto --up westnet-eastnet-ikev2
ipsec showstates
sleep 45
ipsec showstates
echo done
