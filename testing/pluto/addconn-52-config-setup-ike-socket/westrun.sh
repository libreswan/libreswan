/testing/guestbin/swan-prep --nokeys
echo "initdone"

# Test 1: options from config setup in ipsec.conf
ipsec pluto --config west.conf
../../guestbin/wait-until-pluto-started
ipsec status | grep "ikebuf="
ipsec whack --shutdown

# Test 2: options from command line arguments
ipsec pluto --config west-cli.conf --ike-socket-errqueue=no --ike-socket-bufsize=65535
../../guestbin/wait-until-pluto-started
ipsec status | grep "ikebuf="
ipsec whack --shutdown

echo done
