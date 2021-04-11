/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/block-non-ipsec.sh
ipsec auto --add road-east
echo initdone
ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate
ping -n -q -c 4 192.0.2.254
sleep 2
ipsec whack --trafficstatus
echo done
