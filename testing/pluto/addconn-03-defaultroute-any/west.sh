/testing/guestbin/swan-prep
./ips.sh
ipsec start
../../guestbin/wait-until-pluto-started
ipsec addconn --verbose test
# base line check - remove routes and try again
# systemctl restart network.service
# ipsec start
# C=`ip -o route show scope global |wc -l`; echo "Global routes $C"
# ipsec addconn --verbose test

