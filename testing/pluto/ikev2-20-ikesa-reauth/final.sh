ipsec whack --trafficstatus
# either west or westnet-eastnet-ikev2
ipsec connectionstatus | grep "established .* SA"
