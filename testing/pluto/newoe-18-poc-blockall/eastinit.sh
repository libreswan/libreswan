/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "0.0.0.0/0"  >> /etc/ipsec.d/policies/block
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
echo "initdone"
