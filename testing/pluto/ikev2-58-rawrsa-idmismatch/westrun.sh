ipsec whack --impair suppress-retransmits
# this connection will fail
ipsec auto --up west-westnet-eastnet
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# note the ID is @west
ipsec auto --listpubkeys
# delete this connection and load the same one as on the east.
ipsec auto --delete west-westnet-eastnet
ipsec auto --status | grep west-westnet-eastnet
# why the public keys from the deleted still around?
ipsec auto --listpubkeys
ipsec auto --add east-westnet-eastnet
ipsec auto --listpubkeys
# this should succeed
ipsec auto --up east-westnet-eastnet
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo done
