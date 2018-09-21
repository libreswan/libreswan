/testing/guestbin/swan-prep 
/usr/bin/pk12util -i /testing/x509/strongswan/strongEast.p12 -d sql:/etc/ipsec.d -w /testing/x509/nss-pw
# Tuomo: why doesn't ipsec checknss --settrust work here?
certutil -M -d sql:/etc/ipsec.d -n "strongSwan CA - strongSwan" -t CT,,
#ipsec start
ipsec _stackmanager start
ipsec pluto --config /etc/ipsec.conf --leak-detective
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
