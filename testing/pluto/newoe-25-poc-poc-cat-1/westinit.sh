/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.0.0.0/8"  >> /etc/ipsec.d/policies/private-or-clear
# east and west share the same ikev2-oe.conf while road has a diferent one.
cp east.ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 2
echo "initdone"
