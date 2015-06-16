/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.0.2.0/24" >> /etc/ipsec.d/policies/private-or-clear
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
echo "initdone"
