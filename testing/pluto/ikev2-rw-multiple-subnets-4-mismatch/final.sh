# order of conns is not stable, let's just check if we have our 6 tunnels
ipsec trafficstatus | wc -l
ipsec _kernel state
ipsec _kernel policy
