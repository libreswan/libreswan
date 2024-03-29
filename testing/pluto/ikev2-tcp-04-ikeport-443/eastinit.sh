/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east
# block all TCP and UDP port 500 and 4500
iptables -I INPUT -p udp --dport 500 -j DROP
iptables -I INPUT -p udp --dport 4500 -j DROP
iptables -I INPUT -p tcp --dport 4500 -j DROP
echo "initdone"
