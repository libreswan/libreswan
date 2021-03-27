/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/clear-or-private
cp ikev2-east-oe.conf /etc/ipsec.d/ikev2-oe.conf
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
../../pluto/bin/wait-for.sh --match 'loaded 9,' -- ipsec auto --status
echo "initdone"
