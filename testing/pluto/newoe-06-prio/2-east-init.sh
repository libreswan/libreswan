/testing/guestbin/swan-prep --hostkeys
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24" >> /etc/ipsec.d/policies/clear-or-private
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east-ikev2
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 11' -- ipsec auto --status
echo "initdone"
