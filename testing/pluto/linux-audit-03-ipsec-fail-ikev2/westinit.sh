/testing/guestbin/swan-prep --hostkeys
setenforce 1
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-ipsec-fail
#ipsec whack --impair timeout_on_retransmit
echo "initdone"
ipsec whack --impair revival
