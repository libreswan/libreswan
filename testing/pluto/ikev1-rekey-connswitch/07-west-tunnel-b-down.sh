ipsec auto --down TUNNEL-B
#One IKE will remain on TUNNEL-B
ipsec auto --status | grep TUNNEL
