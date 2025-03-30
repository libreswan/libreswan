
# down before unroute; everything but trap cleared
ipsec auto --down initiator
ipsec _kernel policy
ipsec _kernel state

# now clear everything
ipsec unroute initiator
ipsec _kernel policy
