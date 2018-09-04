# fail
ipsec whack --xauthname 'use2' --xauthpass '' --name xauth-road-eastnet-psk --initiate
# pass
ipsec whack --xauthname 'nopw' --xauthpass '' --name xauth-road-eastnet-psk --initiate
sleep 5
ping -n -c 4 192.0.2.254
ipsec whack --trafficstatus
# note there should NOT be any incomplete IKE SA attempting to do ModeCFG or EVENT_v1_RETRANSMIT
ipsec status |grep STATE
echo done
