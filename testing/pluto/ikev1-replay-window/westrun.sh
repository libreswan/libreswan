ipsec whack --listen > /dev/null
ipsec auto --up westnet-eastnet-default
ip xfrm state |grep replay-window
grep replay-window /tmp/pluto.log
ipsec restart
../../guestbin/wait-until-pluto-started
ipsec whack --listen > /dev/null
ipsec auto --up westnet-eastnet-zero
ip xfrm state |grep replay-window
grep replay-window /tmp/pluto.log
ipsec restart
../../guestbin/wait-until-pluto-started
# there is a kernel bug in deplaying "new style" replay-window?
ipsec whack --listen > /dev/null
ipsec auto --up westnet-eastnet-64
ip xfrm state |grep replay-window
grep replay-window /tmp/pluto.log
echo done
