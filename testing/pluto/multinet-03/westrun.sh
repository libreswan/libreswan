ipsec auto --up westnet-eastnet-subnets
ipsec whack --trafficstatus | sort
# rekey
sleep 5
ipsec auto --up westnet-eastnet-subnets
ipsec whack --trafficstatus | sort
ipsec showstates | sort
echo done
