/testing/guestbin/swan-prep
# block plaintext port 22
echo "test plaintext" | nc -s 192.0.1.254 192.0.2.254 22
iptables -A  INPUT -i eth1 -s 192.0.2.254/32 -p tcp --sport 22 -j LOGDROP
iptables -I  INPUT -m policy --dir in --pol ipsec -j ACCEPT
echo "test block" | nc -s 192.0.1.254 192.0.2.254 22
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec auto --add westnet-eastnet-22
ipsec auto --route westnet-eastnet-22
echo "initdone"
