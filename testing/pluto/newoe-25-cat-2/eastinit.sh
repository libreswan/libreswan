/testing/guestbin/swan-prep
# prevent stray DNS packets hitting OE - DNS not used on east in this test
rm /etc/resolv.conf
touch /etc/resolv.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
cp ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 2
echo "initdone"
