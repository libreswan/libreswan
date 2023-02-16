/testing/guestbin/swan-prep --nokeys

NOW=$(date +%s)
THEN=$((${NOW} - 45 * 24 * 60 * 60))

# Generate a sane CA and a sane peer certificate, back-dated by two
# months.  Export these then wipe so that peer has to send the cert
# back.

certutil -m 1 -S -k rsa -x        -w -2 -n new-ca   -s "CN=new-ca"   -v 12 -t "CT,C,C" -d /etc/ipsec.d -z ipsec.conf
certutil -m 2 -S -k rsa -c new-ca       -n new-west -s "CN=new-west" -v 12 -t "u,u,u"  -d /etc/ipsec.d -z ipsec.conf
pk12util -W secret -o OUTPUT/new-west.p12   -n new-west -d /etc/ipsec.d
certutil -L -n new-west -d /etc/ipsec.d -a > OUTPUT/new-west.crt
certutil -F -n new-west -d /etc/ipsec.d

# Now generate a CA that expired 1 month ago.  Use that to sign a
# certificate (for west) that is valid.

certutil -m 1 -S -k rsa -x -w -13 -v 12 -n old-ca  -s "CN=old-ca"  -v 12 -t "CT,C,C" -d /etc/ipsec.d -z ipsec.conf
certutil -m 2 -S -k rsa -c old-ca -w -11 -n old-west -s "CN=old-west" -v 12 -t "u,u,u"  -d /etc/ipsec.d -z ipsec.conf
pk12util -W secret -o OUTPUT/old-west.p12   -n old-west -d /etc/ipsec.d
certutil -L -n old-west -d /etc/ipsec.d -a > OUTPUT/old-west.crt
certutil -F -n old-west -d /etc/ipsec.d

# Now generate a CA that expired 1 month ago.  Use that to sign a
# certificate (for west) that is valid.

certutil -m 1 -S -k rsa -x -w -13 -v 12 -n hog-ca  -s "CN=hog-ca"  -v 12 -t "CT,C,C" -d /etc/ipsec.d -z ipsec.conf
certutil -m 2 -S -k rsa -c hog-ca -w -11 -n hog-west -s "CN=hog-west" -v 12 -t "u,u,u"  -d /etc/ipsec.d -z ipsec.conf
pk12util -W secret -o OUTPUT/hog-west.p12   -n hog-west -d /etc/ipsec.d
certutil -L -n hog-west -d /etc/ipsec.d -a > OUTPUT/hog-west.crt
certutil -F -n hog-west -d /etc/ipsec.d

# Use vfychain to confirm the above settings
#
# -p -p engages the new PKIX interface that pluto is using.
#
# -u 12 -> 1<<12 is #define certificateUsageIPsec (0x1000)
#
# -b YYMMDDHHMMZ (yea, CC is magic)

VFYDATE=$(date -d @${THEN} +%y%m%d000000Z)
/usr/lib64/nss/unsupported-tools/vfychain -v -u 12 -p -p -d /etc/ipsec.d -a OUTPUT/new-west.crt
/usr/lib64/nss/unsupported-tools/vfychain -v -u 12 -p -p -b ${VFYDATE} -d /etc/ipsec.d -a OUTPUT/new-west.crt
! /usr/lib64/nss/unsupported-tools/vfychain -v -u 12 -p -p -d /etc/ipsec.d -a OUTPUT/old-west.crt
/usr/lib64/nss/unsupported-tools/vfychain -v -u 12 -p -p -b ${VFYDATE} -d /etc/ipsec.d -a OUTPUT/old-west.crt
! /usr/lib64/nss/unsupported-tools/vfychain -v -u 12 -p -p -d /etc/ipsec.d -a OUTPUT/hog-west.crt
/usr/lib64/nss/unsupported-tools/vfychain -v -u 12 -p -p -b ${VFYDATE} -d /etc/ipsec.d -a OUTPUT/hog-west.crt
