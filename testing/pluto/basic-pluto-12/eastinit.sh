/testing/guestbin/swan-prep --hostkeys
# block plaintext port 7
#iptables -A INPUT -i eth1 -s 0.0.0.0/0 -p tcp --dport 7 -j DROP
#iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
../../guestbin/echo-server.sh -tcp -4 7 -daemon
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec auto --add westnet-eastnet-7
ipsec auto --route westnet-eastnet-7
echo "initdone"
