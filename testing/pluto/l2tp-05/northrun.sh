ipsec auto --replace north--east-l2tp
ipsec auto --up north--east-l2tp
echo "c server" >/var/run/l2tp-control
sleep 5
ipsec look
ping -c 4 -n 192.0.2.254
telnet 192.0.2.254 2 | wc -l
ifconfig ppp0 | grep 'inet addr'
echo done
