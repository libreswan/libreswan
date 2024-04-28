/testing/guestbin/swan-prep --x509

ipsec certutil -D -n west

ipsec certutil -m 2 -S -k rsa -c east -n west-notyetvalid -s CN=west-notyetvalid -w 1 -v 12 -t u,u,u  -z east.conf
ipsec pk12util -W secret -o OUTPUT/west-notyetvalid.p12 -n west-notyetvalid
ipsec certutil -L -n west-notyetvalid -a > OUTPUT/west-notyetvalid.crt
ipsec certutil -F -n west-notyetvalid

! ipsec vfychain -v -u 12 -p -p -p -a OUTPUT/west-notyetvalid.crt

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
echo "initdone"
