/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
cp resolv.conf /etc
# need to disable ipv6 and activate auto-interface
cp west-unbound.conf /etc/unbound/unbound.conf
# will throw an error about bad unresolvable name
echo "initdone"
