/testing/guestbin/swan-prep --nokeys
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
ipsec auto --add passthrough-in
ipsec auto --route passthrough-in
ipsec auto --add passthrough-out
ipsec auto --route passthrough-out
echo "initdone"
