/testing/guestbin/swan-prep --nokeys
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/private-or-clear
echo "192.1.3.209/32"  >> /etc/ipsec.d/policies/block
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 11,' -- ipsec auto --status
echo "initdone"
