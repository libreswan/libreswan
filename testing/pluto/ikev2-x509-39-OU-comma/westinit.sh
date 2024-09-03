/testing/guestbin/swan-prep --nokeys
rm -f /etc/ipsec.d/*.*
ipsec initnss > /dev/null 2> /dev/null
ipsec pk12util -i OUTPUT/nss/client.p12 -K 'foobar' -W 'foobar'
ipsec certutil -M -n cacert -t 'CT,,'
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add x509
ipsec auto --add x509-comma-comma
# show both conns are interpreted with \,
ipsec status |grep idtype
echo "initdone"
