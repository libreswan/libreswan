/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-aggr
ipsec whack --impair copy_v1_notify_response_SPIs_to_retransmission
ipsec whack --impair revival
ipsec whack --impair timeout-on-retransmit
echo "initdone"
