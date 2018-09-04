# create a partial state on east, don't hold the hack for retransmit
ipsec whack --impair impair-drop-i2 --impair delete-on-retransmit
ipsec auto --up  westnet-eastnet-aggr
# we are waiting for east to expire the partial IKE state in 1+1+2+4+8+16+32 secs
sleep 30
sleep 30
sleep 10
echo done
