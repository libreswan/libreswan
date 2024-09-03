/testing/guestbin/swan-prep --nokeys
export EF_DISABLE_BANNER=1; ipsec pluto  --impair helper_thread_delay:5 --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
echo "initdone"
