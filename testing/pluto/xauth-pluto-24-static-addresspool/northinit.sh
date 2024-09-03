/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/block-non-ipsec.sh
ipsec auto --add north-east
ipsec whack --xauthname 'xnorth' --xauthpass 'use1pass' --name north-east --initiate
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
echo initdone
