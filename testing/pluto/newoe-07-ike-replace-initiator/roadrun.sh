# first ping will be lost in triggering OE
ping -n -c 4 -I 192.1.3.209 192.1.2.23
sleep 1
ipsec status | grep "STATE_" 
# issue a manual rekey of parent
ipsec whack --rekey-ike --name 1
# wait two seconds to ensure old parent has expired
sleep 2
# parent state must be #3 and the latest ISAKMP
ipsec status | grep STATE_
ipsec whack --trafficstatus
ipsec whack --shuntstatus
echo done
