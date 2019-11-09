/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --whackrecord /var/tmp/east.record
ipsec auto --add westnet-eastnet
ipsec whack --debug none --debug control --debug controlmore --debug crypt
