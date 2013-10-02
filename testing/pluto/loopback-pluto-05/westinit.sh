/testing/guestbin/swan-prep 
ipsec _stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
/usr/sbin/sshd -p 666
ipsec auto --add wide
ipsec auto --add narrow
ip xfrm policy
echo "initdone"
