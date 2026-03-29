/testing/guestbin/swan-prep --x509
# remove west's cert so it must come via IKE
ipsec certutil -D -n west
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-x509-cr
ipsec connectionstatus westnet-eastnet-x509-cr
echo "initdone"
