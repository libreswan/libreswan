ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec whack --trafficstatus
sleep 5

# confirm we updated unbound - should not be empty once DNS CP is
# added
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

# Test seccomp actually works - that it records pluto crashing ....
ipsec start
../../guestbin/wait-until-pluto-started

# Since whack hangs - it does not know that pluto died - run it in the
# background.  Give it a few seconds to do its job.
ipsec whack --seccomp-crashtest & sleep 2

# should show 1 entry of pluto crashing now

echo done
