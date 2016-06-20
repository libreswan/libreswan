/testing/guestbin/swan-prep --x509
certutil -D -n north -d sql:/etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east-x509-pluto-02
ipsec auto --status | grep north-east-x509-pluto-02
echo "initdone"
