/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair send_bogus_isakmp_flag
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
