# wait over one minute to ensure no EVENT_SA_REPLACE lingered and started something
sleep 45
sleep 30
# There should be no IKE SA and no IPsec SA
ipsec whack --trafficstatus
# east howvever, should be attempting to connect to west because it has auto=start
ipsec status |grep EVENT_RETRANSMIT | sed "s/EVENT_RETRANSMIT in .*$/EVENT_RETRANSMIT in .../"
