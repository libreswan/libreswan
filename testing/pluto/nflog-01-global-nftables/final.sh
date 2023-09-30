../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
ipsec stop
# show no nflog left behind
# it may leave an empty table ip filter
nft list ruleset
