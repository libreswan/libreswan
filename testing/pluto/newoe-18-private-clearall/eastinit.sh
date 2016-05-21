/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "10.0.0.0/8"  >> /etc/ipsec.d/policies/clear-or-private
echo "192.168.0.0/16"  >> /etc/ipsec.d/policies/clear-or-private
echo "0.0.0.0/0"  >> /etc/ipsec.d/policies/clear
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
echo "initdone"
