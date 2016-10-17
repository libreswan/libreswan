/testing/guestbin/swan-prep
domainname testing.libreswan.org
ipsec setup start
ipsec whack --debug-all --impair-retransmits
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add gssapi
# see if KDC is up by getting a ticket
echo swanswan | kinit admin@TESTING.LIBRESWAN.ORG
klist
echo "initdone"
