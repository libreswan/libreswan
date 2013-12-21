ipsec auto --up northnet-eastnet-nat
echo one
ipsec auto --replace northnet-eastnet-nat
ipsec auto --up northnet-eastnet-nat
echo two
ipsec auto --down northnet-eastnet-nat
sleep 2
ipsec auto --up northnet-eastnet-nat
echo three
echo done
