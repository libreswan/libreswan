/testing/guestbin/swan-prep
ipsec start
#ipsec pluto
/testing/pluto/bin/wait-until-pluto-started
ipsec addconn --verbose west
../bin/check-for-core.sh
