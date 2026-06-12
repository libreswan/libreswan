/testing/guestbin/swan-prep --x509
/testing/x509/import.sh real/mainec/root.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add rw-general
ipsec auto --add rw-specific
ipsec whack --impair suppress_retransmits
ipsec whack --impair omit_v2_notification:SIGNATURE_HASH_ALGORITHMS
echo "initdone"
