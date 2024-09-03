/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-no-sha1
ipsec auto --status
echo "initdone"
ipsec whack --impair revival
