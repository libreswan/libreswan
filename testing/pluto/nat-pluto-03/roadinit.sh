/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add road-eastnet-encapsulation=yes
ipsec status | grep encapsulation:
echo "initdone"
