/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
../bin/block-non-ipsec.sh
ipsec auto --add road-east
echo initdone
ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate
ping -n -c 4 192.0.2.254
sleep 2
ipsec whack --trafficstatus
echo done
