/testing/guestbin/swan-prep --nokeys

# Generate a sane CA and a sane peer certificate.

ipsec certutil -m 1 -S -k rsa -x        -n new-ca   -s "CN=new-ca"   -v 12 -t "CT,C,C" -z ipsec.conf
ipsec certutil -m 2 -S -k rsa -c new-ca -n new-west -s "CN=new-west" -v 12 -t "u,u,u"  -z ipsec.conf
ipsec pk12util -W secret -o OUTPUT/new-west.p12   -n new-west
ipsec certutil -L -n new-west -a > OUTPUT/new-west.crt
ipsec certutil -F -n new-west

# Now generate a CA that expires this month.  Use that to sign a
# certificate (for west) that has just started to be valid and
# slightly more recent than above.

ipsec certutil -m 1 -S -k rsa -x -w -11 -v 12 -n old-ca  -s "CN=old-ca"  -v 12 -t "CT,C,C" -z ipsec.conf
ipsec certutil -m 2 -S -k rsa -c old-ca       -n old-west -s "CN=old-west" -v 12 -t "u,u,u"  -z ipsec.conf
ipsec pk12util -W secret -o OUTPUT/old-west.p12   -n old-west
ipsec certutil -L -n old-west -a > OUTPUT/old-west.crt
ipsec certutil -F -n old-west

ipsec vfychain to confirm the above settings
#
# -p -p engages the new PKIX interface that pluto is using.
#
# -u 12 -> 1<<12 is #define certificateUsageIPsec (0x1000)
#
# -b YYMMDDHHMMZ (yea, CC is magic)

ipsec vfychain -v -u 12 -p -p -a OUTPUT/new-west.crt
ipsec vfychain -v -u 12 -p -p -a OUTPUT/old-west.crt
