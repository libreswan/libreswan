# we cannot set impair retransmits, as strongswan attempts to get OCSP/CRL
# which takes longer then our Quick Mode msg.
#ipsec whack --impair retransmits
# this should succeed
ipsec auto --up san
echo "done"
