/testing/guestbin/swan-prep --nokeys
ipsec pk12util -i /testing/x509/strongswan/strongEast.p12 -w /testing/x509/nss-pw
# Tuomo: why doesn't ipsec checknss --settrust work here?
ipsec certutil -M -n "strongSwan CA - strongSwan" -t CT,,
#ipsec start
ipsec pluto --config /etc/ipsec.conf --leak-detective
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec whack --impair suppress_retransmits
ipsec whack --impair force_v2_auth_method:ecdsa_sha2_384_p384
ipsec whack --impair omit_v2_notification:SIGNATURE_HASH_ALGORITHMS
echo "initdone"
