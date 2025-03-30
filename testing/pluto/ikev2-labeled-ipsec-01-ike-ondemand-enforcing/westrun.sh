# IKE will be triggered by acquire; expect two labels
ipsec auto --route labeled
ipsec _kernel state
ipsec _kernel policy
# trigger acquire using the predefined ping_t context
../../guestbin/ping-once.sh --runcon "system_u:system_r:ping_t:s0:c1.c256" --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match 192.1.2.23 -- ipsec trafficstatus
../../guestbin/ping-once.sh --runcon "system_u:system_r:ping_t:s0:c1.c256" --up     -I 192.1.2.45 192.1.2.23
# there should be 1 tunnel in each direction
ipsec trafficstatus
# there should be no bare shunts
ipsec shuntstatus
# let larval state expire
../../guestbin/wait-for.sh --no-match ' spi 0x00000000 ' -- ipsec _kernel state
echo done
