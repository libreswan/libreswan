../../guestbin/swan-prep

# Run the parser tests.

ipsec algparse -tp -v1
ipsec algparse -tp -v1 -pfs
ipsec algparse -tp -v2
ipsec algparse -tp -v2 -pfs

ipsec algparse -tp -v2 -pfs -addke

# Run the algorithm tests; there should be no fails.

ipsec algparse -ta > /dev/null

# Check pluto is starting in the correct mode.

ipsec start
../../guestbin/wait-until-pluto-started
grep ^FIPS /tmp/pluto.log

# Check pluto algorithm list.

sed -n -e '/^|/d' -e '/Encryption Algorithm.*:/,/^testing/ p' /tmp/pluto.log
