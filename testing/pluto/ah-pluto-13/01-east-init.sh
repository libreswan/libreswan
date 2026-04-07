/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ah-sha1-pfs
ipsec status | grep westnet-eastnet-ah-sha1-pfs
echo "initdone"
