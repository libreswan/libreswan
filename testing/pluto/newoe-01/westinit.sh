/testing/guestbin/swan-prep
named -c /etc/bind/named.conf
cp policies/* /etc/ipsec.d/policies/
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
#ipsec whack --myid @west.testing.libreswan.org
ipsec auto --status
echo "initdone"
