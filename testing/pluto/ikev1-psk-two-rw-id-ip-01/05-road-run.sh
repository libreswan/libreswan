ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate
# bonus ping for different count
../../pluto/bin/ping-once.sh --up -I 192.0.2.102 192.0.2.254
../../pluto/bin/ping-once.sh --up -I 192.0.2.102 192.0.2.254
ipsec whack --trafficstatus
echo done
