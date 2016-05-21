/testing/guestbin/swan-prep --x509
# remove west's cert so it must come via IKE
certutil -D -n west -d sql:/etc/ipsec.d
certutil -D -n west-ec -d sql:/etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509-cr
ipsec auto --status | grep westnet-eastnet-x509-cr
echo "initdone"
