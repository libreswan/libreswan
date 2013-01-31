: ==== start ====
# /testing/guestbin/swan-prep --testname `basename $PWD` --x509 

/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started

iptables -I OUTPUT -f -d 192.1.2.45 -j LOGDROP
ipsec auto --add westnet-eastnet-x509-fragmentation
ipsec auto --status
echo "initdone"
