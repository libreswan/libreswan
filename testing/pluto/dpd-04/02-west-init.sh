/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east
ipsec add west-eastnet
ipsec add westnet-east
# don't auto-revive, instead wait for a trigger
ipsec whack --impair revival
echo "initdone"
