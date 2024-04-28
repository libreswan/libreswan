/testing/guestbin/swan-prep --x509

ipsec certutil -D -n west
ipsec pk12util -i OUTPUT/east-notyetvalid.p12 -W secret

mkdir -p /var/run/pluto

# Set a time in the future so notyetvalid and east certs are valid
# here.  Invoke pluto directly so that it is the root of the shared
# faketime tree.
LD_PRELOAD=/usr/lib64/faketime/libfaketime.so.1 FAKETIME=+370d ipsec pluto  --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started

# if faketime works, adding conn should not give a warning about cert
ipsec auto --add nss-cert
echo "initdone"
