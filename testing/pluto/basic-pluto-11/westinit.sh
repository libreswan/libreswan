/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-send-key-size-check --impair-retransmits
ipsec auto --add westnet-eastnet-3des
ipsec auto --status |grep westnet-eastnet-3des
echo "initdone"
