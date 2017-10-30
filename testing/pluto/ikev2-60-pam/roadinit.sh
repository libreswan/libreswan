iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j DROP
/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet
echo done
