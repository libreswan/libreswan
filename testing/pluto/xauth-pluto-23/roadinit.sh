/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east
../bin/block-non-ipsec.sh
ipsec whack --xauthname 'road' --xauthpass 'roadpass' --name road-east --initiate
ping -w 4 -n -c 4 192.0.2.254
ipsec whack --trafficstatus
echo initdone
