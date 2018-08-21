/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
../bin/block-non-ipsec.sh
ipsec auto --add north-east
# re-uses same username, should not cause problems
ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name north-east --initiate
ping -n -c 4 -I 192.0.2.201 192.0.2.254
ipsec whack --trafficstatus
echo initdone
