../../guestbin/prep.sh

ipsec start
../../guestbin/wait-until-pluto-started

ipsec -n --briefstatus
ipsec    --briefstatus

# now for some fun
ln -s /var/run/pluto/pluto.ctl /tmp/tmp.ctl

ipsec -n --ctlsocket /tmp/tmp.ctl whack --briefstatus
ipsec    --ctlsocket /tmp/tmp.ctl whack --briefstatus

ipsec -n whack --ctlsocket /tmp/tmp.ctl --briefstatus
ipsec    whack --ctlsocket /tmp/tmp.ctl --briefstatus
