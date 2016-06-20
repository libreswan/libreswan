/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24" >> /etc/ipsec.d/policies/clear-or-private
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east-ikev2
# give OE policies time to load
sleep 5
echo "initdone"
