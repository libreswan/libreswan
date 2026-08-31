/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainec/`hostname`.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec whack --impair suppress_retransmits
ipsec whack --impair force_v2_auth_method:ecdsa_sha2_384_p384
ipsec whack --impair emit_v2N_SIGNATURE_HASH_ALGORITHMS:omit
echo "initdone"
