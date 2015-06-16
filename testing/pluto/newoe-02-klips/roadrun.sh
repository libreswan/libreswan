ping -n -c 4 -I 192.1.3.209 192.1.2.23
ping -n -c 2 -I 192.1.3.209 7.7.7.7
# wait OE retransmits and rekeying
sleep 5
ipsec whack --shuntstatus
# if 7.7.7.7 shows as %pass, we should be able to ping it
ping -n -c 2 -I 192.1.3.209 7.7.7.7
echo done
