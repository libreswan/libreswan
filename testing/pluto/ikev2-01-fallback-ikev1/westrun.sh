ipsec auto --up  westnet-eastnet-ikev2-fallback
# we lose whack just before the fallback to ikev1, give it some time
sleep 15 
sleep 15 
sleep 15 
ipsec auto --status |grep STATE_MAIN_I4
ping -n -c 2 -I 192.0.1.254 192.0.2.254
echo done
