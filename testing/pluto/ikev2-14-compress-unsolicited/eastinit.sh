/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ipcomp
ipsec whack --impair add_v2_notification:IPCOMP_SUPPORTED
echo "initdone"
