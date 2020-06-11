/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
../bin/block-non-ipsec.sh
ipsec auto --add north-east
ipsec whack --impair suppress-retransmits
ipsec whack --xauthname 'use1' --xauthpass 'use1pass' --name north-east --initiate
../../pluto/bin/ping-once.sh --up -I 192.0.2.101 192.0.2.254
ipsec whack --trafficstatus
echo initdone
