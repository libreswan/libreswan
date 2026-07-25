/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/road.end.cert
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.209/32"  >> /etc/ipsec.d/policies/private
# do not start yet
echo "initdone"
