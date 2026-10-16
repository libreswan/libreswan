/testing/guestbin/swan-prep
# prevent stray DNS packets hitting OE - DNS not used in this test
echo > /etc/resolv.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24" >> /etc/ipsec.d/policies/private-or-clear
echo "192.1.3.0/24" >> /etc/ipsec.d/policies/private-or-clear
cp ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec status
echo "initdone"
