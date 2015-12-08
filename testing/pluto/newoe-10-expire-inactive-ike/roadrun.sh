ping -n -c 4 -I 192.1.3.209 192.1.2.23
sleep 5
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# wait for IKE SA to expire due to inactivity.
sleep 60
sleep 60
sleep 50
# expired #1  and #2. trafficstatus  should be empty
ipsec whack --trafficstatus
ipsec look
#establish a new one
ping -n -c 4 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
ipsec look
echo done
