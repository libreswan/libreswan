ipsec auto --up road
../../pluto/bin/ping-once.sh --up 192.0.2.254
ipsec whack --impair send-no-delete
ipsec stop
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north
ipsec auto --up north
echo done
