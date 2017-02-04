# wait for east to initiate to us
sleep 10
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# sending delete/notify should cause east to re-initiate 
ipsec auto --down west-east-auto
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# give Delete/Notify some time
sleep 5
# A new IPsec SA should be established (without patch takes 30 seconds)
ipsec whack --trafficstatus
sleep 20
ipsec whack --trafficstatus
sleep 10
ipsec whack --trafficstatus
