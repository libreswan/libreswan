ipsec pluto --version |grep 'IPsec profile' > /dev/null || echo "pluto not compiled with HAS_NSS_IPSEC_PROFILE" && exit 
/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"
