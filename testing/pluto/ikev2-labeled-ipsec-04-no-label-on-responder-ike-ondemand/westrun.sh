ipsec whack --impair suppress_retransmits
# IKE will be triggered by acquire; expect two labels
ipsec auto --route labeled
ipsec _kernel state
ipsec _kernel policy
# trigger acquire using the predefined ping_t context; won't work
../../guestbin/ping-once.sh --runcon "system_u:system_r:ping_t:s0:c1.c256" --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for-pluto.sh 'TS_UNACCEPTABLE'
# there should be 0 tunnels - child rejected
ipsec trafficstatus
# there should be no bare shunts
ipsec shuntstatus
# let larval state expire
../../guestbin/wait-for.sh --no-match ' spi 0x00000000 ' -- ipsec _kernel state
echo done
