ipsec auto --add xauth-road-eastnet-psk
ipsec whack --xauthname 'use2' --xauthpass 'use1pass' --name xauth-road-eastnet-psk --initiate
# let a few DPD probes happen
sleep 10
ipsec auto --up xauth-road-eastnet-psk
sleep 10
echo done
