ipsec auto --up westnet-eastnet-ikev2
ping -q -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ping -s 512 -n -c  15 -I 192.0.1.254 192.0.2.254
#Child #3 with traffic
ipsec whack --trafficstatus
echo "sleep 60  seconds, east reauthenticate IKE and Child SA"
sleep 30
sleep 30
# it should have IKE #4 Child #5 and also IKE #1 and Child #3
ipsec status | grep westnet-eastnet-ikev2
ping -n -c  4 -I 192.0.1.254 192.0.2.254
# there should be traffic on #3 and #5
ipsec whack --trafficstatus
# wait for west to EXPIRE  #1, #3 #4 as IKE and #6 as Child (rekeyed by east)
sleep 50
ping -n -c  4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done
