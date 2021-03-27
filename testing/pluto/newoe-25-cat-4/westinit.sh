/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/clear-or-private
cp ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
../../pluto/bin/wait-for.sh --match 'loaded 9,' -- ipsec auto --status
ping -c 4 -I 192.1.2.45 192.1.2.23
echo "initdone"
