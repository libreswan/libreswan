/testing/guestbin/swan-prep --x509
ipsec certutil -D -n north
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add north-east-x509-pluto-02
ipsec connectionstatus north-east-x509-pluto-02
echo "initdone"
