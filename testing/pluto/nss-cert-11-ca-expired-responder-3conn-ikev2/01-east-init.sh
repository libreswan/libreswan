/testing/guestbin/swan-prep --nokeys

# Generate three CA+cert pairs.
#
# new-ca+new-cert: a sane CA and a sane peer certificate, back-dated
# by two months (-v12 -w -1).
#
# old-ca+old-west: generate a CA that expired 1 month ago (-v 12 -w
# -13).  Use that to sign a certificate (for west) that is valid.
#
# hog-ca+hog=west: same; CA expired 1 month ago (-v 12 -w -13).  Use
# that to sign a certificate (for west) that is valid.

ipsec certutil -m 1 -S -k rsa -x        -w -2 -n new-ca   -s "CN=new-ca"   -v 12 -t "CT,C,C" -z ipsec.conf
ipsec certutil -m 2 -S -k rsa -c new-ca       -n new-west -s "CN=new-west" -v 12 -t "u,u,u"  -z ipsec.conf

ipsec certutil -m 1 -S -k rsa -x -w -13 -v 12 -n old-ca  -s "CN=old-ca"  -v 12 -t "CT,C,C" -z ipsec.conf
ipsec certutil -m 2 -S -k rsa -c old-ca -w -11 -n old-west -s "CN=old-west" -v 12 -t "u,u,u"  -z ipsec.conf

ipsec certutil -m 1 -S -k rsa -x -w -13 -v 12 -n hog-ca  -s "CN=hog-ca"  -v 12 -t "CT,C,C" -z ipsec.conf
ipsec certutil -m 2 -S -k rsa -c hog-ca -w -11 -n hog-west -s "CN=hog-west" -v 12 -t "u,u,u"  -z ipsec.conf

# Export the generated certificates and then delete them.  This forces
# west to send the cert as part of IKE_AUTH.

ipsec pk12util -W secret -o OUTPUT/hog-west.p12   -n hog-west
ipsec pk12util -W secret -o OUTPUT/new-west.p12   -n new-west
ipsec pk12util -W secret -o OUTPUT/old-west.p12   -n old-west

ipsec certutil -L -n hog-west -a > OUTPUT/hog-west.crt
ipsec certutil -L -n new-west -a > OUTPUT/new-west.crt
ipsec certutil -L -n old-west -a > OUTPUT/old-west.crt

ipsec certutil -F -n hog-west
ipsec certutil -F -n new-west
ipsec certutil -F -n old-west

# ipsec vfychain to confirm the above settings
#
# -p -p engages the new PKIX interface that pluto is using.
#
# -u 12 -> 1<<12 is #define certificateUsageIPsec (0x1000)
#
# -b YYMMDDHHMMZ (yea, CC is magic)

NOW=$(date +%s)
THEN=$((${NOW} - 45 * 24 * 60 * 60))
VFYDATE=$(date -d @${THEN} +%y%m%d000000Z)
ipsec vfychain -v -u 12 -p -p -a OUTPUT/new-west.crt
ipsec vfychain -v -u 12 -p -p -b ${VFYDATE} -a OUTPUT/new-west.crt
! ipsec vfychain -v -u 12 -p -p -a OUTPUT/old-west.crt
ipsec vfychain -v -u 12 -p -p -b ${VFYDATE} -a OUTPUT/old-west.crt
! ipsec vfychain -v -u 12 -p -p -a OUTPUT/hog-west.crt
ipsec vfychain -v -u 12 -p -p -b ${VFYDATE} -a OUTPUT/hog-west.crt
