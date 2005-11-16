ipsec setup start
ipsec auto --config /testing/pluto/bad-updown-01/ipsec.conf.bad-updown --add westnet-eastnet-bad-updown
/testing/pluto/bin/eroutewait.sh trap
ipsec auto --route westnet-eastnet-bad-updown
# check if Pluto is still alive
ipsec whack --listen

echo done westinit

