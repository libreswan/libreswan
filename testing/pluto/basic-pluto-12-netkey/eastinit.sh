/testing/guestbin/swan-prep
# block plaintext port 22
#iptables -A INPUT -i eth1 -s 0.0.0.0/0 -p tcp --dport 22 -j LOGDROP
#iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec auto --add westnet-eastnet-22
ipsec auto --route westnet-eastnet-22
# SHOULD NOT see 222 (but ESP) and SHOULD see 22 (from passthrough)
tcpdump -nn -i eth1 esp or port 22 or port 222 &
echo "initdone"
