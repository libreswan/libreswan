ipsec auto --up west-east-delete1
ping -n -c 2 -I 192.0.1.254 192.0.2.254
ipsec auto --status
echo "sleeping a bit.. 2"
sleep 2
ipsec whack --deletestate 2
echo "sleeping a bit.. 2"
sleep 2
ipsec auto --status
ipsec look
ip xfrm pol
ip xfrm state
echo done
