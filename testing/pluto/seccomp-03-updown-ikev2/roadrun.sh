ipsec up westnet-eastnet-ipv4-psk-ikev2
ipsec trafficstatus

# confirm we updated unbound - should not be empty once DNS CP is
# added

unbound-control list_forwards
ipsec down westnet-eastnet-ipv4-psk-ikev2

# try some things to trigger new syscalls

ipsec status > /dev/null
ipsec whack --listen > /dev/null
ipsec globalstatus > /dev/null
ipsec shuntstatus > /dev/null
ipsec secrets > /dev/null
ipsec delete westnet-eastnet-ipv4-psk-ikev2
ipsec stop

# ensure seccomp did not kill pluto - should not show any hits

ausearch -ts recent -i -m SECCOMP

# Test seccomp actually works - that it records pluto crashing ....

ipsec start
../../guestbin/wait-until-pluto-started

# Since whack hangs - it does not know that pluto died - run it in the
# background.  Give it a few seconds to do its job.

ipsec whack --seccomp-crashtest & pid=$! ; sleep 2
kill ${pid} ; sleep 1

# should show 1 entry of pluto crashing now

ausearch -ts recent -i -m SECCOMP | sed -e "s/ ip=[^ ]* / ip=XXX /" -e "s/ pid=[^ ]* / pid=XXX /" -e "s/msg=audit(.*) /msg=audit(XXX) /"

# cleanup the zombie child; systemctl asks the console for its size!
# And remove ctl files

nohup systemctl daemon-reexec > OUTPUT/$(hostname).systemd-restart.log
rm /var/run/pluto/*

echo done
