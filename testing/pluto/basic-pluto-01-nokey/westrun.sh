ipsec whack --debug-all --impair retransmits
# this is expected to fail to to our own misconfigured key
ipsec auto --up  westnet-eastnet
# we should not see any leftover states
ipsec status |grep STATE_
echo done
