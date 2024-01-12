/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair tcp_use_blocking_write
ipsec add westnet-eastnet-ikev2
echo "initdone"
