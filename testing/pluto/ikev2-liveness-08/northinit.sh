/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east-x509-ipv4
ipsec auto --up north-east-x509-ipv4
ping -n -c4 -I 192.0.2.100 192.1.2.23
ipsec whack --trafficstatus
#block all traffic to east. tunnel will clear
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
echo "initdone"
