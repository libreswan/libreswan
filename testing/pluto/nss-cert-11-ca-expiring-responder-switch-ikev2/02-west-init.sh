/testing/guestbin/swan-prep --nokeys

# Generate west's CA and then use that to generate a signed
# cert+private-key that east can present when authenticating.  All
# dates for these certs are sane.

ipsec certutil -m 1 -S -k rsa -x         -n west-ca -s "CN=west-ca"  -v 12 -t "CT,C,C" -z ipsec.conf
ipsec certutil -m 2 -S -k rsa -c west-ca -n east    -s "CN=east" -v 12 -t "u,u,u"  -z ipsec.conf
ipsec pk12util -W secret -o OUTPUT/east.p12 -n east
ipsec certutil -L -n east -a > OUTPUT/east.crt
ipsec certutil -F -n east
