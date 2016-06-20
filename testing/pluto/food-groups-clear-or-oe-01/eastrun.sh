
dig 23.2.1.192.in-addr.arpa. txt
/testing/pluto/bin/look-for-txt 23.2.1.192.in-addr.arpa. AQN3cn11F

ipsec start

/testing/pluto/basic-pluto-01/eroutewait.sh trap

ipsec auto --add clear-or-private
ipsec whack --listen
ipsec auto --route clear-or-private
# don't route, it's passive.
ipsec whack --debug-oppo --debug-control

ipsec look
ping -c 1 -n 192.0.1.1
sleep 5
ping -c 8 -n 192.0.1.1
ipsec look
: ==== cut ====
cat /tmp/pluto.log
: ==== tuc ====
echo end eastrun.sh

