/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east
# block IKE and ESP over UDP
iptables -I INPUT -p udp --dport 500 -j DROP
iptables -I INPUT -p udp --dport 4500 -j DROP
echo "initdone"
