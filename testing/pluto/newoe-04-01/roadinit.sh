/testing/guestbin/swan-prep
named -c /etc/bind/named.conf
cp policies/* /etc/ipsec.d/policies/
#echo "192.1.3.209/32" >> /etc/ipsec.d/policies/clear
ping -n -c 2 -I 192.1.3.209 7.7.7.7
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --status
echo "initdone"
