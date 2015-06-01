ipsec auto --up  westnet-eastnet-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# shows state numbers 1 and 2
ipsec status |grep STATE_ | sed "s/EVENT_SA_REPLACE.*/......../"
# wait for rekey event
sleep 30
sleep 30
# shows state numbers 3 and 4 - 1 and 2 should have been replaced
ipsec status |grep STATE_ | sed "s/EVENT_SA_REPLACE.*/......../"
echo done
