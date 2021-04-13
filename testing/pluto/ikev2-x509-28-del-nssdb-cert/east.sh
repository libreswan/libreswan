/testing/guestbin/swan-prep --x509

ipsec start
../../guestbin/wait-until-pluto-started

# list certs in NSS DB
ipsec whack --listcerts | grep east

# add / remove 'test'
ipsec auto --add test
ipsec auto --delete test

# delete certificate east
certutil -d sql:/etc/ipsec.d -D -n east
# whack should not show certificate
ipsec whack --listcerts | grep east

# try a load; should fail
ipsec auto --add test
ipsec auto --delete test

# put east back
certutil -A -i ../../x509/certs/east.crt -d sql:/etc/ipsec.d -n east -t "P,,"

# re-load should not dump core
ipsec auto --add test
ipsec auto --delete test
