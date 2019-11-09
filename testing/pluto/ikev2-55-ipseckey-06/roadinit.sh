/testing/guestbin/swan-prep --hostname north
iptables -A INPUT -i eth0 -s 192.1.2.0/24 -p icmp -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east-ikev2
ipsec whack --impair suppress-retransmits
# road should have only one public key of its own
ipsec auto --listpubkeys
ipsec whack --trafficstatus
echo "initdone"
