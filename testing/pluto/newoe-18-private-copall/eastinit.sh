/testing/guestbin/swan-prep --nokeys
cp policies/* /etc/ipsec.d/policies/
echo "10.0.0.0/8"  >> /etc/ipsec.d/policies/clear-or-private
echo "192.168.0.0/16"  >> /etc/ipsec.d/policies/clear-or-private
echo "0.0.0.0/0"  >> /etc/ipsec.d/policies/clear-or-private
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 12' -- ipsec auto --status
echo "initdone"
