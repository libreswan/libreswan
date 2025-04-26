/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east

ipsec whack --impair add_v2_notification:IKEV2_FRAGMENTATION_SUPPORTED
echo "initdone"
