/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec whack --impair ignore_v2_notification:SIGNATURE_HASH_ALGORITHMS
echo "initdone"
