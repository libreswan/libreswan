/testing/guestbin/swan-prep
# prevent stray DNS packets hitting OE - DNS not used on east in this test
rm /etc/resolv.conf
touch /etc/resolv.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
cp ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 9,' -- ipsec auto --status
echo "initdone"
