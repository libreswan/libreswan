/testing/guestbin/swan-prep
named -c /etc/bind/named.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.45/32" >> /etc/ipsec.d/policies/clear
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
#ipsec whack --myid @west.testing.libreswan.org
ipsec auto --status
echo "initdone"
