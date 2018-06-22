ipsec auto --up westnet-eastnet-ikev2a
ping -w 1 -q -n -c 4 -I 192.0.1.254 192.0.2.254
# These two conns are mismatched and should fail
# The whack should release the socket on receiving NO_PROPOSAL_CHOSEN
ipsec auto --up westnet-eastnet-ikev2b
ipsec auto --up westnet-eastnet-ikev2c
#
# should see westnet-eastnet-ikev2b expiring
# should see westnet-eastnet-ikev2c replacing
ipsec auto --delete westnet-eastnet-ikev2a
ipsec status | grep westnet-eastnet
echo done
