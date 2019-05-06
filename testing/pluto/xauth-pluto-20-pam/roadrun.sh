ipsec whack --impair suppress-retransmits
ipsec whack --xauthname 'baduser' --xauthpass 'use1pass' --name xauth-road-eastnet --initiate
# prevent revive race
sleep 3
ipsec whack --xauthname 'gooduser' --xauthpass 'use1pass' --name xauth-road-eastnet --initiate
ping -n -c4 192.0.2.254
ipsec trafficstatus
echo done
