# we cannot set impair retransmits, as strongswan attempts to get OCSP/CRL
# which takes longer then our Quick Mode msg.
#ipsec whack --impair suppress-retransmits
# this should succeed
ipsec auto --up san
echo "done"
