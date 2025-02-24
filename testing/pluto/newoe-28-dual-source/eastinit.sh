/testing/guestbin/swan-prep --nokeys
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/private
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load and route
sleep 5
echo "initdone"
