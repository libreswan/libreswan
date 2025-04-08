/testing/guestbin/swan-prep --nokeys

# Import the root CA, and use that to generate a cert+pubkey that's
# valid in 1 month (-w 1) and expires in 12 months (-v 12).
/testing/x509/import.sh real/mainca/root.p12
ipsec certutil -m 2 -S -k rsa -c mainca -n west-expired -s CN=west-expired -w -12 -v 6 -t CT,, -z ipsec.conf
ipsec certutil -L

# verify the result
ipsec certutil -L -a -n west-expired -o OUTPUT/west-expired.crt
! ipsec vfychain -v -u 12 -p -p -p -a OUTPUT/west-expired.crt

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west
ipsec checkpubkeys

echo "initdone"
