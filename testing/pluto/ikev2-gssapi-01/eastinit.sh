/testing/guestbin/swan-prep
domainname testing.libreswan.org
ipsec setup start
ipsec whack --impair suppress_retransmits
../../guestbin/wait-until-pluto-started
ipsec auto --add gssapi
# see if KDC is up by getting a ticket
echo swanswan | kinit admin@TESTING.LIBRESWAN.ORG
klist
echo "initdone"
