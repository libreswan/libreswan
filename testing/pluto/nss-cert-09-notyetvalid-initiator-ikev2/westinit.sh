/testing/guestbin/swan-prep --x509 --x509name notyetvalid
certutil -d sql:/etc/ipsec.d -D -n east
ipsec _stackmanager start
mkdir -p /var/run/pluto

# Set a time in the future so notyetvalid and east certs are valid
# here.  Invoke pluto directly so that it is the root of the shared
# faketime tree.
LD_PRELOAD=/usr/lib64/faketime/libfaketime.so.1 FAKETIME=+370d ipsec pluto  --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started

# if faketime works, adding conn should not give a warning about cert
ipsec auto --add nss-cert
echo "initdone"
