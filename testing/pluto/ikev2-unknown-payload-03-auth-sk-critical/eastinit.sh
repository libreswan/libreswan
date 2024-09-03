/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair add_unknown_v2_payload_to_sk:IKE_AUTH
ipsec whack --impair unknown_v2_payload_critical
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
