#east is the initiator
sleep 10
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec stop
# wait till east retransmit delay get to bigger.
sleep 17
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --up westnet-eastnet-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "sleep 33 seconds. there should be only one Child SA after this"
sleep 13
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done
