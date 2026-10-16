/testing/guestbin/swan-prep
# prevent stray DNS packets hitting OE - DNS not used in this test
echo > /etc/resolv.conf
cp policies/* /etc/ipsec.d/policies/
cp ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
echo "192.1.2.0/24" >> /etc/ipsec.d/policies/private-or-clear
echo "192.1.3.33/32" >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec status
echo "initdone"
