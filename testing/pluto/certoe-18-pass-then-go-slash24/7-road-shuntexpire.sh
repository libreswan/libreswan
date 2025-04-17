# letting 60s shunt expire
../../guestbin/wait-for.sh --timeout 60 --no-match ' spi 0x00000000 ' -- ipsec _kernel state
# we should have 1 or 2 tunnels, no shunts
ipsec trafficstatus
ipsec shuntstatus
# we should see one of each in/fwd/out (confirming %pass shunt delete didn't take out dir out tunnel policy
ipsec _kernel policy
# nic blocks cleartext, so confirm tunnel is working
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec trafficstatus
