# wait for east to initiate to us
sleep 10
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec whack --trafficstatus
# sending delete/notify should cause east to re-initiate 
ipsec auto --down west-east-auto
sleep 5
# A new IPsec SA should be established (without patch takes 30 seconds)
ipsec whack --trafficstatus
# traffic flow should still work
../../guestbin/ping-once.sh --up 192.1.2.23
sleep 20
ipsec whack --trafficstatus
