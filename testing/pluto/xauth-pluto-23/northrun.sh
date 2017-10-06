../bin/block-non-ipsec.sh
ipsec whack --xauthname 'north' --xauthpass 'northpass' --name north-east --initiate
ping -n -c 4 192.0.2.254
ipsec whack --trafficstatus
echo done
