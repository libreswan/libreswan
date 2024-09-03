/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair send_bogus_dcookie
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
