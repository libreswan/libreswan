/testing/guestbin/swan-prep --x509

ipsec start
../../guestbin/wait-until-pluto-started

# list certs in NSS DB
ipsec whack --listcerts | grep east

# add / remove 'test'
ipsec auto --add test
ipsec auto --delete test

# delete certificate east
ipsec certutil -D -n east
# whack should not show certificate
ipsec whack --listcerts | grep east

# try a load; should fail
ipsec auto --add test
ipsec auto --delete test

# put east back
ipsec certutil -A -i /testing/x509/real/mainca/east.end.cert -n east -t "P,,"

# re-load should not dump core
ipsec auto --add test
ipsec auto --delete test
