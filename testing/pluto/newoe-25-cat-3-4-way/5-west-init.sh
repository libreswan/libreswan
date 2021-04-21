/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/clear-or-private
cp ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
# start; give OE policies time to load
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
echo "initdone"
