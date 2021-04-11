/testing/guestbin/swan-prep
export PLUTO_CRYPTO_HELPER_DELAY=5; export EF_DISABLE_BANNER=1; ipsec pluto  --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east
ipsec whack --impair revival
ipsec whack --impair suppress-retransmits
echo "initdone"
