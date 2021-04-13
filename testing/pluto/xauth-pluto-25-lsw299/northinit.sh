/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/block-non-ipsec.sh
ipsec auto --add north-east
# note - initiating during "init" when multiple hosts/namespaces are starting up is unwise - race conditions
# let east startup and load conns
sleep 10
ipsec whack --xauthname 'xnorth' --xauthpass 'use1pass' --name north-east --initiate
sleep 2
ping -n -q -c 4 -w 4 -I 192.0.2.101 192.0.2.254
sleep 5
ipsec whack --trafficstatus
echo initdone
