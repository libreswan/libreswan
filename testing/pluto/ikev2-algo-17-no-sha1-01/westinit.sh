/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-no-sha1
ipsec status
echo "initdone"
ipsec whack --impair revival
