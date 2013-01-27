: ==== start ====
TESTNAME=basic-pluto-11
/testing/guestbin/swan-prep --testname $TESTNAME

ipsec setup stop
pidof pluto >/dev/null && killall pluto 2> /dev/null
rm -fr /var/run/pluto/pluto.pid
/usr/local/libexec/ipsec/_stackmanager stop
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-ipv4  
## seems psk need an up on both sides AA
## ipsec auto --up westnet-eastnet-ipv4 
echo "initdone"
