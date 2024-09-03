/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
# suffer a quick death
ipsec whack --impair timeout_on_retransmit
ipsec auto --add westnet-eastnet
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
