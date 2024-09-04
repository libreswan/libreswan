/testing/guestbin/swan-prep --hostkeys
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24" >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10' -- ipsec auto --status
ipsec auto --add road-east-ikev2
echo "initdone"
