/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
../bin/block-non-ipsec.sh
ipsec auto --add north-east
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name north-east --initiate
ping -n -c 4 -w 4 -I 192.0.2.100 192.0.2.254
ipsec whack --trafficstatus
echo initdone
