/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name north-east --initiate
ping -n -c 4 -w 4 -I 192.168.11.100 192.1.2.23
echo initdone
