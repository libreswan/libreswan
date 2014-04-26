: ==== start ====
/testing/guestbin/swan-prep

ipsec setup stop
/usr/local/libexec/ipsec/_stackmanager stop
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add west-east-delete1

echo "initdone"
