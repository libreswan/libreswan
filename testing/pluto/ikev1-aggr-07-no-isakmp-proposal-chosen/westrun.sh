# create a partial state on east, don't hold the hack for retransmit
ipsec whack --impair revival
ipsec auto --up westnet-eastnet-aggr
echo done
