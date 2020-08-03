/testing/guestbin/swan-prep
./ips.sh
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec addconn --verbose test
# base line check - remove routes and try again
# systemctl restart network.service
# ipsec start
# C=`ip -o route show scope global |wc -l`; echo "Global routes $C"
# ipsec addconn --verbose test
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====

