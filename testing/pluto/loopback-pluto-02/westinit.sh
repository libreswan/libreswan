#/testing/guestbin/swan-prep
# confirm that the network is alive
ping -n -c 4 127.0.0.1
# make sure that clear text does not get through
iptables -A INPUT -i lo -p tcp --dport 4300  -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec setup start
# openswan only - libreswan does this in _stackmanager
echo 0 >/proc/sys/net/ipv4/conf/lo/disable_xfrm
echo 0 >/proc/sys/net/ipv4/conf/lo/disable_policy
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add loopback-westleft
ipsec auto --add loopback-westright
echo "initdone"
