/testing/guestbin/swan-prep --nokeys

# Generate two CA and certificate pairs:
#
# new-ca+new-west: the CA is valid for twelve months back-dated by two
# months (-w 2 -v 12); same for the certificate (i.e., valid now and
# 45 days ago).
#
# old-ca+old-west: this time the CA expired a month ago (-w -13 -v 12)
# and use this to sign a cert that is still valid (just) (-w -11 -v
# 12) (i.e., both are valid 45 days ago, and cert can't be verified).

ipsec certutil -m 1 -S -k rsa -x -w -2 -n new-ca -s CN=new-ca -v 12 -t CT,C,C -z ipsec.conf
ipsec certutil -m 2 -S -k rsa -c new-ca -n new-west -s CN=new-west -v 12 -t u,u,u  -z ipsec.conf

ipsec certutil -m 1 -S -k rsa -x -w -13 -v 12 -n old-ca -s CN=old-ca  -v 12 -t CT,C,C -z ipsec.conf
ipsec certutil -m 2 -S -k rsa -c old-ca -w -11 -n old-west -s CN=old-west -v 12 -t u,u,u  -z ipsec.conf

# Export the certs old-west and new-west both as p12s and as .crts
# (the latter is fed to verify) and then delete them so that the peer
# has to include them in the IKE_AUTH request.

ipsec pk12util -W secret -o OUTPUT/new-west.p12 -n new-west
ipsec pk12util -W secret -o OUTPUT/old-west.p12 -n old-west

ipsec certutil -L -n new-west -a > OUTPUT/new-west.crt
ipsec certutil -L -n old-west -a > OUTPUT/old-west.crt

ipsec certutil -F -n new-west
ipsec certutil -F -n old-west

# Use ipsec vfychain to confirm the above settings
#
# -p -p engages the new PKIX interface that pluto is using.
#
# -u 12 -> 1<<12 is #define certificateUsageIPsec (0x1000)
#
# -b YYMMDDHHMMZ (yea, CC is magic)
#
# THEN is 45 days ago which is when everything was valid (just before
# old-ca expires).

NOW=$(date +%s)
THEN=$((${NOW} - 45 * 24 * 60 * 60))
VFYDATE=$(date -d @${THEN} +%y%m%d000000Z)

ipsec vfychain -v -u 12 -p -p -a OUTPUT/new-west.crt
! ipsec vfychain -v -u 12 -p -p -b ${VFYDATE} -a OUTPUT/new-west.crt
! ipsec vfychain -v -u 12 -p -p -a OUTPUT/old-west.crt
ipsec vfychain -v -u 12 -p -p -b ${VFYDATE} -a OUTPUT/old-west.crt
