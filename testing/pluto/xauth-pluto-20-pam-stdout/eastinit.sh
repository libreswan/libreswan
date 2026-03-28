/testing/guestbin/swan-prep --hostkeys

cp pluto.sh  /etc/pam.d/pluto.sh
cp pluto.pam /etc/pam.d/pluto

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add xauth-road-eastnet
echo "initdone"
