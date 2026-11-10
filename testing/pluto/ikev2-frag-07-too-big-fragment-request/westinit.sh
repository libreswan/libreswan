/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.p12
/testing/x509/import.sh real/mainca/east.end.cert

ipsec start
../../guestbin/wait-until-pluto-started

# bloat the first fragment
ipsec whack --impair add_unknown_v2_payload_to:IKE_AUTH:400

# And send some small bonus fragments making the total >64.
ipsec whack --impair add_fragments:64:100

ipsec add west-east
echo "initdone"
