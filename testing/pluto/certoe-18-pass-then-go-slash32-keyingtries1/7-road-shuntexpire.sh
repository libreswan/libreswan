# letting 60s shunt expire
sleep 30
sleep 30
# we should have 1 or 2 tunnels, no shunts
ipsec trafficstatus
ipsec shuntstatus
# we should see one of each in/fwd/out (confirming %pass shunt delete didn't take out dir out tunnel policy
ip xfrm pol
# nic blocks cleartext, so confirm tunnel is working
ping -n -q -c 4 -I 192.1.3.209 192.1.2.23
ipsec trafficstatus
: ==== end ====
