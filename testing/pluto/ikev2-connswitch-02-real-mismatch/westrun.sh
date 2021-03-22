ipsec auto --up westnet-eastnet-foo
# expected to fail
ipsec whack --impair delete-on-retransmit
ipsec auto --up westnet-eastnet-bar
echo done
