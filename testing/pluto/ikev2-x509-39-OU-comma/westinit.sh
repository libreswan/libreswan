/testing/guestbin/swan-prep
rm -f /etc/ipsec.d/*.*
ipsec initnss > /dev/null 2> /dev/null
pk12util -i /testing/x509/nss/client.p12 -d sql:/etc/ipsec.d -K 'foobar' -W 'foobar'
certutil -M -d sql:/etc/ipsec.d -n cacert -t 'CT,,'
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add x509
ipsec auto --add x509-comma-comma
# show both conns are interpreted with \,
ipsec status |grep idtype
echo "initdone"
