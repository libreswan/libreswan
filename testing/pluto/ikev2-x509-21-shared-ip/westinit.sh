/testing/guestbin/swan-prep --x509
certutil -D -n east -d sql:/etc/ipsec.d
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/otherca/otherwest.p12
echo "initdone"
