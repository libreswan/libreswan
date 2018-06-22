/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east
ipsec whack --xauthname 'xnorth' --xauthpass 'use1pass' --name north-east --initiate
ping -q -w 4 -n -c 4 192.0.2.254
ipsec whack --trafficstatus
echo initdone
