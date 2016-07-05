ipsec auto --up  west-east
# suppress martian logging before we create havoc
echo 0 > /proc/sys/net/ipv4/conf/default/log_martians
echo 0 > /proc/sys/net/ipv4/conf/all/log_martians
# add east's ip on west to shoot in foot
ip addr add 192.1.2.23/24 dev eth1
ipsec auto --ready
sleep 30
echo done
