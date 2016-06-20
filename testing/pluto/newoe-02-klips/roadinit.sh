/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
ping -n -c 4 -I 192.1.3.209 7.7.7.7
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
echo "initdone"
