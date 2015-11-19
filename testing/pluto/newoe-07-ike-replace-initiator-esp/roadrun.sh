ping -n -c 4 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 20
ping -n -c 4 -I 192.1.3.209 192.1.2.23
sleep 20
ping -n -c 4 -I 192.1.3.209 192.1.2.23
sleep 20
ping -n -c 4 -I 192.1.3.209 192.1.2.23
sleep 20
ping -n -c 4 -I 192.1.3.209 192.1.2.23
# Should state state #4 to indicate it has rekeyed
ipsec whack --trafficstatus
ipsec whack --shuntstatus
killall ip > /dev/null 2> /dev/null
echo done
