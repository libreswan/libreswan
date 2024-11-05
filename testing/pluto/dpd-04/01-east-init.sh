/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/ipsec-add.sh westnet-east west-eastnet west-east
echo "initdone"
