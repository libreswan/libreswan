/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair ke_payload:empty
ipsec whack --impair suppress_retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-slow
echo "initdone"
