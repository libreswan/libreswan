ipsec whack --impair drop-incoming:4
ipsec whack --xauthname 'use1' --xauthpass 'use1pass' --name xauth-road-eastnet --initiate
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
# note there should NOT be any incomplete IKE SA attempting to do ModeCFG
ipsec status |grep STATE
echo done
