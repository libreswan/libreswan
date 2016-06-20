/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
cp ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 10
ping -c 4 -I 192.1.2.45 192.1.2.23
echo "initdone"
