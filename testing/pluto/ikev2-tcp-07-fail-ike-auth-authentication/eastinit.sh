/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east

# force east into legacy mode
ipsec whack --impair v2N_SIGNATURE_HASH_ALGORITHMS:ignore
ipsec whack --impair v2N_SIGNATURE_HASH_ALGORITHMS:emit_never
echo "initdone"
