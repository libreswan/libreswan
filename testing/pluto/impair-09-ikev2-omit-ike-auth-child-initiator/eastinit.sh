/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair omit_v2_ike_auth_child
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
