/testing/guestbin/swan-prep --x509
# remove west's cert so it must come via IKE
ipsec certutil -D -n west
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509-cr
ipsec auto --status | grep westnet-eastnet-x509-cr
echo "initdone"
