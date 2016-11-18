ipsec auto --status | grep westnet-eastnet-ipv4-psk-ikev2
#sleep for more than PENDING_PHASE2_INTERVAL > 121s
sleep 30
sleep 30
sleep 30
sleep 30
sleep 1
ipsec auto --status | grep westnet-eastnet-ipv4-psk-ikev2
# this should find a match
grep "replacing phase 1" /tmp/pluto.log
echo done
