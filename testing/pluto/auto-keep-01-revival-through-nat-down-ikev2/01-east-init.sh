/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
# loaded via ipsec.conf - no ipsec keep yet

# Late in the game there will be a revival attempt; make it pause so
# it can be run manually.

ipsec whack --impair revival

echo "initdone"
