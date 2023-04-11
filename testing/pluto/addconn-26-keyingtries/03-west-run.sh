ipsec whack --impair ke-payload:omit
ipsec whack --impair revival  # give up after N retry attempts

ipsec auto --add  westnet-eastnet
ipsec auto --add  westnet-eastnet-k0
ipsec auto --add  westnet-eastnet-k1
ipsec auto --add  westnet-eastnet-k2
ipsec auto --add  nevernegotiate

ipsec auto --up westnet-eastnet-k2
ipsec auto --delete westnet-eastnet-k2

echo done
