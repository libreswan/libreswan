/testing/guestbin/swan-prep --nokeys

cp policy /etc/ipsec.d/policies/road

ipsec start
../../guestbin/wait-until-pluto-started

echo "initdone"
