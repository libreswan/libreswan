/testing/guestbin/swan-prep --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add rw-eastnet-ipv6
ipsec status
echo "initdone"
