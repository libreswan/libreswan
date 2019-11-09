/testing/guestbin/swan-prep
ipsec start
# empty results in no ike=/esp= lines, so results in our own defaults, which don't show up
update-crypto-policies --set EMPTY
ipsec auto --add system-policy-test
ipsec status |grep system-policy-test | grep algorithms:
update-crypto-policies --set DEFAULT
ipsec auto --add system-policy-test
ipsec status |grep system-policy-test | grep algorithms:
update-crypto-policies --set FUTURE
ipsec auto --add system-policy-test
ipsec status |grep system-policy-test | grep algorithms:
update-crypto-policies --set NEXT
ipsec auto --add system-policy-test
ipsec status |grep system-policy-test | grep algorithms:
update-crypto-policies --set FIPS
ipsec auto --add system-policy-test
ipsec status |grep system-policy-test | grep algorithms:
update-crypto-policies --set LEGACY
ipsec auto --add system-policy-test
ipsec status |grep system-policy-test | grep algorithms:
echo "initdone"
