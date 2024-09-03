/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair add_v2_notification:MOBIKE_SUPPORTED
echo "initdone"
