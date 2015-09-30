ipsec auto --add xauth-road-eastnet-psk
ipsec whack --xauthname 'use2' --xauthpass 'use1pass' --name xauth-road-eastnet-psk --initiate
sleep 5
ipsec auto --up xauth-road--eastnet-psk
echo done
