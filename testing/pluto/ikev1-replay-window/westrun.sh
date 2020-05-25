ipsec auto --up westnet-eastnet-default
ip xfrm state |grep replay-window
grep replay-window /tmp/pluto.log
ipsec restart
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --up westnet-eastnet-zero
ip xfrm state |grep replay-window
grep replay-window /tmp/pluto.log
ipsec restart
/testing/pluto/bin/wait-until-pluto-started
# there is a kernel bug in deplaying "new style" replay-window?
ipsec auto --up westnet-eastnet-64
ip xfrm state |grep replay-window
grep replay-window /tmp/pluto.log
echo done
