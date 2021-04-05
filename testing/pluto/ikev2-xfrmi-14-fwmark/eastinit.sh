/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnet
ncat -k -l -c "printf 'HTTP/1.1 200 OK\r\n\r\ncool, thanks\n'" -p 8888&
echo "initdone"
