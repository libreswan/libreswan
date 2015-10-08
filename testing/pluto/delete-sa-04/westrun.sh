# wait for east to initiate to us
sleep 30
ipsec whack --trafficstatus
# use delete, not down - because east has auto=start
ipsec auto --delete west-east-auto
# give Delete/Notify some time
sleep 5
# no IPsec SA should be there. No ISAKMP SA should be there either
ipsec whack --trafficstatus
ipsec status |grep west-east
