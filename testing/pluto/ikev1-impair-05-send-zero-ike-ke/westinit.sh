/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ipv4-psk
ipsec whack --impair revival
echo "initdone"
