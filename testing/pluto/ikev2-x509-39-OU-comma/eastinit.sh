/testing/guestbin/swan-prep
# always zap and recreate special comma certs
rm /etc/ipsec.d/*.*
/testing/x509/nss-certs.sh
ipsec initnss > /dev/null 2> /dev/null
pk12util -i /testing/x509/nss/server.p12 -d sql:/etc/ipsec.d -K 'foobar' -W 'foobar'
certutil -M -d sql:/etc/ipsec.d -n cacert -t 'CT,,'
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add x509
echo "initdone"
