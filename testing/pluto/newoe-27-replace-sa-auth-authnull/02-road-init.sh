/testing/guestbin/swan-prep --nokeys
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add authenticated
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 11,' -- ipsec auto --status
echo "initdone"
