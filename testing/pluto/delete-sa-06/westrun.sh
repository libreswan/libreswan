# wait for east to initiate to us
sleep 10
ipsec whack --trafficstatus
# sending delete/notify should cause east to re-initiate
ipsec auto --down west-east-auto
# give Delete/Notify some time
sleep 5
# A new IPsec SA should be established (without patch takes 30 seconds)
ipsec whack --trafficstatus
sleep 20
ipsec whack --trafficstatus
sleep 10
ipsec whack --trafficstatus
