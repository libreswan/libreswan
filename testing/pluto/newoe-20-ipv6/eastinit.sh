/testing/guestbin/swan-prep --6
cp policies/* /etc/ipsec.d/policies/
echo "2001:db8:1:3::0/64" >> /etc/ipsec.d/policies/private-or-clear
echo "2001:db8:1:3::254/128" >> /etc/ipsec.d/policies/clear
echo "2001:db8:1:2::254/128" >> /etc/ipsec.d/policies/clear
echo "fe80::/10" >> /etc/ipsec.d/policies/clear
cp /source/programs/configs/v6neighbor-hole.conf /etc/ipsec.d/
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
echo "initdone"
