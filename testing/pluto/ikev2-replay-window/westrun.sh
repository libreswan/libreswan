ipsec auto --up westnet-eastnet-default
ip xfrm state |grep replay
grep 'kernel: .*replay-window' /tmp/pluto.log
ipsec restart
../../guestbin/wait-until-pluto-started
ipsec auto --up westnet-eastnet-zero
ip xfrm state |grep replay
grep 'kernel: .*replay-window' /tmp/pluto.log
ipsec restart
../../guestbin/wait-until-pluto-started
# there is a kernel bug in deplaying "new style" replay-window?
ipsec auto --up westnet-eastnet-256
ip xfrm state |grep replay
grep 'kernel: .*replay-window' /tmp/pluto.log
echo done
