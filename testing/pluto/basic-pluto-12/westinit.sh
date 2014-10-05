/testing/guestbin/swan-prep
iptables -A OUTPUT -o eth1 -s 192.0.1.254/32 -p tcp --dport 22 -j LOGDROP
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec auto --add westnet-eastnet-22
ipsec auto --route westnet-eastnet-22
echo "initdone"
