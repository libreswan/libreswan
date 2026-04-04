/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add common
ipsec whack --impair log_rate_limit:2
echo "initdone"
