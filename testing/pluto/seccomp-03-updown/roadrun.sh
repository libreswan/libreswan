ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
ipsec whack --trafficstatus
sleep 5
# confirm we updated unbound - should not be empty once DNS CP is added 
unbound-control list_forwards
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
# try some things to trigger new syscalls
ipsec status > /dev/null
ipsec whack --listen > /dev/null
ipsec whack --globalstatus > /dev/null
ipsec whack --shuntstatus > /dev/null
ipsec secrets > /dev/null
ipsec auto --delete westnet-eastnet-ipv4-psk-ikev2
ipsec stop
# ensure seccomp did not kill pluto - should not show any hits
ausearch -ts recent -i -m SECCOMP
# and also test seccomp actually works
ipsec start
sleep 3
ipsec whack --seccomp-crashtest &
# should show 1 entry now
ausearch -ts recent -i -m SECCOMP | sed -e "s/ ip=[^ ]* / ip=XXX /" -e "s/ pid=[^ ]* / pid=XXX /" -e "s/msg=audit(.*) /msg=audit(XXX) /"
echo done
