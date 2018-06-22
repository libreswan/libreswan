# this is expected to fail to our own misconfigured key
ipsec auto --up  westnet-eastnet
# we should NOT see more than one of our own outcoming attempts
ipsec status
echo done
