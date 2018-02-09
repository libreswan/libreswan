../../guestbin/swan-prep

../bin/algparse.sh /usr/local/libexec/ipsec/algparse algparse*.txt

# start pluto
ipsec start
/testing/pluto/bin/wait-until-pluto-started

# check pluto in correct FIPS mode
grep ^FIPS /tmp/pluto.log

# check pluto algorithm list
sed -n -e '/^|/d' -e ':algs / algorithms:/ { :alg ; p ; n ; /^  / b alg ; b algs }' /tmp/pluto.log
