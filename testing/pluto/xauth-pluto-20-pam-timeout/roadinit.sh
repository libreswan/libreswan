iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j DROP
/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add xauth-road-eastnet
ipsec whack --impair revival
echo done
