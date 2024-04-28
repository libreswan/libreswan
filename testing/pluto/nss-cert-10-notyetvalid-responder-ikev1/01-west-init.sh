/testing/guestbin/swan-prep --x509
ipsec certutil -D -n east

ipsec certutil -m 2 -S -k rsa -c west -n east-notyetvalid -s CN=east-notyetvalid -w 1 -v 12 -t u,u,u  -z east.conf
ipsec pk12util -W secret -o OUTPUT/east-notyetvalid.p12 -n east-notyetvalid
ipsec certutil -L -n east-notyetvalid -a > OUTPUT/east-notyetvalid.crt
ipsec certutil -F -n east-notyetvalid

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
echo "initdone"
