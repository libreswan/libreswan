../../guestbin/swan-prep --fips

# Run the parser tests.
#
# The output is a patch showing differences so to update run something
# like:
#    algparse.sh ... | patch

../../guestbin/algparse.sh 'ipsec algparse' algparse*.txt > /dev/null

# Run the algorithm tests; there should be no fails.

ipsec algparse -ta > /dev/null

# Check that pluto is starting in the correct mode.

ipsec start
../../guestbin/wait-until-pluto-started
grep ^FIPS /tmp/pluto.log

# Check pluto algorithm list.

sed -n -e '/^|/d' -e ':algs / algorithms:/ { :alg ; p ; n ; /^  / b alg ; b algs }' /tmp/pluto.log
