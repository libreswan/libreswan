# connection will fail to establish
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name road-east --initiate
ping -w 4 -q -n -c 4 192.1.2.23
echo done
