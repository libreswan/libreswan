/testing/guestbin/swan-prep --nokeys

cp policy /etc/ipsec.d/policies/road

# need to use pluto
ipsec pluto --config /etc/ipsec.conf --expire-shunt-interval 5s --leak-detective
../../guestbin/wait-until-pluto-started

echo "initdone"
