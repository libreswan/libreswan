../../guestbin/ipsec-look.sh
ipsec stop
# show no nflog left behind
# it may leave an empty table ip filter
nft list ruleset
