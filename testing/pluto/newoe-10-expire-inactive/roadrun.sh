ping -n -c 4 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 5
ipsec whack --trafficstatus
ipsec whack --shuntstatus
sleep 60
sleep 60
ipsec whack --trafficstatus
ipsec look
echo done
