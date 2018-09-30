# wait for east to initiate to us
sleep 30
ipsec whack --trafficstatus
# delete instead of down so it won't re-establish due to east auto=start
ipsec auto --delete west-east-auto
sleep 2
# We should still have the ISAKMP SA for west-east-auto2
ipsec status |grep west-east | grep STATE_
