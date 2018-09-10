/testing/guestbin/swan-prep 
# next two line should not be needed
certutil -A -i /testing/x509/strongswan/strongEastCert.der -n "strongEast" -t "P,," -d sql:/etc/ipsec.d/
certutil -A -i /testing/x509/strongswan/strongWestCert.der -n "strongWest" -t "P,," -d sql:/etc/ipsec.d/
/usr/bin/pk12util -i /testing/x509/strongswan/strongEast.p12 -d sql:/etc/ipsec.d -w /testing/x509/nss-pw
# Tuomo: why doesn't ipsec checknss --settrust work here?
certutil -M -d sql:/etc/ipsec.d -n "strongSwan CA - strongSwan" -t CT,,
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
#tcpdump -w OUTPUT/swan12.pcap -i eth0 -c 1000
echo "initdone"
