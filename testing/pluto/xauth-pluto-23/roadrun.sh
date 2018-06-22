../bin/block-non-ipsec.sh
ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate
ping -q -w 4 -n -c 4 192.0.2.254
ipsec whack --trafficstatus
echo done
