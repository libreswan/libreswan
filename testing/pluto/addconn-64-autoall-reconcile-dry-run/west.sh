/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):   conn serial: \([^;]*\);.*/\1 \2/p' | sort

# nothing changes
ipsec add --autoall --dry-run --config /testing/pluto/addconn-64-autoall-reconcile-dry-run/west-modified.conf
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):   conn serial: \([^;]*\);.*/\1 \2/p' | sort

# the real run does what the dry run said
ipsec add --autoall --config /testing/pluto/addconn-64-autoall-reconcile-dry-run/west-modified.conf
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):   conn serial: \([^;]*\);.*/\1 \2/p' | sort
