/testing/guestbin/swan-prep --nokeys

# Import the root CA, and use that to generate a cert+pubkey that's
# valid in 1 month (-w 1) and expires in 12 months (-v 12).
/testing/x509/import.sh real/mainca/root.p12
ipsec certutil -m 2 -S -k rsa -c mainca -n `hostname`-notyetvalid -s CN=`hostname`-notyetvalid -w 1 -v 12 -t CT,, -z east.conf
ipsec certutil -L

# verify the result
ipsec certutil -L -a -n `hostname`-notyetvalid -o OUTPUT/`hostname`-notyetvalid.crt
! ipsec vfychain -v -u 12 -p -p -p -a OUTPUT/`hostname`-notyetvalid.crt

ipsec start
../../guestbin/wait-until-pluto-started

# beware the groundhog!
ipsec add nss-cert
echo "initdone"
