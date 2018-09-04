ipsec whack --impair suppress-retransmits
# this is expected to fail to our own misconfigured key
ipsec auto --up  westnet-eastnet
# we should not see any leftover states
ipsec status |grep STATE_
echo done
