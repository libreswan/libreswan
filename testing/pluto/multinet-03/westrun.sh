ipsec auto --up  westnet-eastnet-subnets
ipsec whack --trafficstatus | sort
# rekey
sleep 5
ipsec auto --up  westnet-eastnet-subnets
ipsec whack --trafficstatus | sort
ipsec status | grep STATE_ | sort
echo done
