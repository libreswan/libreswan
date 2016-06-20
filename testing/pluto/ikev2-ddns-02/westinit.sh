/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
cp resolv.conf /etc
# need to disable ipv6 and activate auto-interface
cp west-unbound.conf /etc/unbound/
# will throw an error about bad unresolvable name
ipsec auto --add named
echo "initdone"
