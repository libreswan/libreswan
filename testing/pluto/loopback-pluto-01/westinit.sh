/testing/guestbin/swan-prep
# confirm that the network is alive
ping -n -c 4 127.0.0.1
# make sure that clear text does not get through
iptables -A INPUT -i lo -p icmp  -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping 
ping -n -c 4 127.0.0.1
ipsec setup start
# Really only needed for openswan - libreswan _stackmanager does this already
echo 0 >/proc/sys/net/ipv4/conf/lo/disable_xfrm
echo 0 >/proc/sys/net/ipv4/conf/lo/disable_policy
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add loopback-west
echo "initdone"
