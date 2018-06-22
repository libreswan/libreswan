# Should bring up ikev1 connection
ipsec auto --up  westnet-eastnet1
# Should not re-use the existing ikev1 IKE SA, but a start a new ikev2 IKE SA
ipsec auto --up  westnet-eastnet2
echo done
