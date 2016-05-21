/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
ipsec auto --add passthrough-in
ipsec auto --route passthrough-in
ipsec auto --add passthrough-out
ipsec auto --route passthrough-out
echo "initdone"
