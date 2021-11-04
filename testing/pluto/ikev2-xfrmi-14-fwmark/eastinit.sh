/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnet
socat TCP-LISTEN:8888,crlf SYSTEM:"echo HTTP/1.0 200; echo ; echo cool thanks" &
echo "initdone"
