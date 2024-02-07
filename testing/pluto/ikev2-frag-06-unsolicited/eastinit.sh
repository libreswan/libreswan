/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
ipsec whack --impair add_v2_notification:IKEV2_FRAGMENTATION_SUPPORTED
echo "initdone"
