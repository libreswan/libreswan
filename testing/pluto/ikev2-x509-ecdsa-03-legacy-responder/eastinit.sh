/testing/guestbin/swan-prep
/usr/bin/pk12util -i /testing/x509/strongswan/strongEast.p12 -d sql:/etc/ipsec.d -w /testing/x509/nss-pw
# Tuomo: why doesn't ipsec checknss --settrust work here?
certutil -M -d sql:/etc/ipsec.d -n "strongSwan CA - strongSwan" -t CT,,
#ipsec start
ipsec pluto --config /etc/ipsec.conf --leak-detective
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec whack --impair suppress-retransmits
ipsec whack --impair force-v2-auth-method:ecdsa_sha2_384_p384
ipsec whack --impair omit-v2n-signature-hash-algorithms
echo "initdone"
