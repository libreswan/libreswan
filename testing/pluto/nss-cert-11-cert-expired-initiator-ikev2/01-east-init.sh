/testing/guestbin/swan-prep --nokeys

# Generate a sane CA and a sane peer certificate, back-dated by a few
# months.  Export these then wipe so that peer has to send the cert
# back.

certutil -m 1 -S -k rsa -x        -w -2 -n new-ca   -s "CN=new-ca"   -v 12 -t "CT,C,C" -d /etc/ipsec.d -z ipsec.conf
certutil -m 2 -S -k rsa -c new-ca -w -2 -n new-west -s "CN=new-west" -v 12 -t "u,u,u"  -d /etc/ipsec.d -z ipsec.conf
pk12util -W secret -o OUTPUT/new-west.p12   -n new-west -d /etc/ipsec.d
certutil -L -n new-west -d /etc/ipsec.d -a > OUTPUT/new-west.crt
certutil -F -n new-west -d /etc/ipsec.d

/usr/lib64/nss/unsupported-tools/vfychain -p -p -d /etc/ipsec.d -a OUTPUT/new-west.crt
/usr/lib64/nss/unsupported-tools/vfychain -p -p -b 2212300000Z -d /etc/ipsec.d -a OUTPUT/new-west.crt

# Now generate an expired certificate; these two overlap but a month
# ago.

certutil -m 1 -S -k rsa -x -w -13 -n old-ca  -s "CN=old-ca"  -v 12 -t "CT,C,C" -d /etc/ipsec.d -z ipsec.conf
certutil -m 2 -S -k rsa -c old-ca -w -11 -n old-west -s "CN=old-west" -v 12 -t "u,u,u"  -d /etc/ipsec.d -z ipsec.conf
pk12util -W secret -o OUTPUT/old-west.p12   -n old-west -d /etc/ipsec.d
certutil -L -n old-west -d /etc/ipsec.d -a > OUTPUT/old-west.crt
certutil -F -n old-west -d /etc/ipsec.d

/usr/lib64/nss/unsupported-tools/vfychain -p -p -d /etc/ipsec.d -a OUTPUT/old-west.crt
/usr/lib64/nss/unsupported-tools/vfychain -p -p -b 2212300000Z -d /etc/ipsec.d -a OUTPUT/old-west.crt
