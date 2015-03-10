/testing/guestbin/swan-prep
named -c /etc/bind/named.conf
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --myid @east.testing.libreswan.org
ipsec auto --status
echo "initdone"
