/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
ip addr add 192.1.3.210/24 dev eth0
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
echo "initdone"
