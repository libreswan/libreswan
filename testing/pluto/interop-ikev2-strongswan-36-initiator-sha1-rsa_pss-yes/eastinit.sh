/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/`hostname`.p12
/testing/x509/import.sh real/mainca/west.end.cert

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
ipsec whack --impair v2N_SIGNATURE_HASH_ALGORITHMS:emit_never

echo "initdone"
