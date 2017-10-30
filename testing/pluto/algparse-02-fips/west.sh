../../guestbin/swan-prep --fips
../bin/algparse.sh /usr/local/libexec/ipsec/algparse algparse*.txt
ipsec start
/testing/pluto/bin/wait-until-pluto-started
grep ^FIPS /tmp/pluto.log
sed -n -e '/^|/d' -e '/ algorithms:/ { :loop ; p ; n ; /^  / b loop }' /tmp/pluto.log
