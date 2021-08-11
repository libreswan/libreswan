ipsec whack --impair delete-on-retransmit
# IKE will be triggered by acquire; expect two labels
ipsec auto --route labeled
../../guestbin/ipsec-look.sh
# trigger acquire using the predefined ping_t context; won't work
../../guestbin/ping-once.sh --runcon "system_u:system_r:ping_t:s0:c1.c256" --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match '^[^|].*TS_UNACCEPTABLE' -- cat /tmp/pluto.log
# there should be 0 tunnels - child rejected
ipsec trafficstatus
# there should be no bare shunts
ipsec shuntstatus
# let larval state expire
../../guestbin/wait-for.sh --no-match ' spi 0x00000000 ' -- ip xfrm state
echo done
