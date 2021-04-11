../../guestbin/swan-prep --fips

# run the parser tests
../../guestbin/algparse.sh 'ipsec algparse' algparse*.txt > /dev/null

# run the algorithm tests
ipsec algparse -ta > /dev/null

# check pluto is starting in the correct mode
ipsec start
../../guestbin/wait-until-pluto-started
grep ^FIPS /tmp/pluto.log

# check pluto algorithm list
sed -n -e '/^|/d' -e ':algs / algorithms:/ { :alg ; p ; n ; /^  / b alg ; b algs }' /tmp/pluto.log
