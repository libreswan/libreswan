../../guestbin/swan-prep

# run the parser tests
../bin/algparse.sh /usr/local/libexec/ipsec/algparse algparse*.txt

# run the algorithm tests
/usr/local/libexec/ipsec/algparse -ta

# check pluto is starting in the correct mode
ipsec start
/testing/pluto/bin/wait-until-pluto-started
grep ^FIPS /tmp/pluto.log

# check pluto algorithm list
sed -n -e '/^|/d' -e ':algs / algorithms:/ { :alg ; p ; n ; /^  / b alg ; b algs }' /tmp/pluto.log
