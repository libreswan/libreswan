# Check that mainca is present
crlutil -L -d sql:/etc/ipsec.d | grep mainca
# DANGER: race.
#
# Wait for the CRL fetch helper to be triggered and fetch the CRLs.
# The first fetch, which happens happens after 5s, may or may-not be
# too quick for the exchange.
../../guestbin/wait-for.sh --match 'imported CRL.*CN=nic.testing.libreswan.org' -- cat /tmp/pluto.log
../../guestbin/wait-for.sh --match 'imported CRL.*CN=hashsha1.testing.libreswan.org' -- cat /tmp/pluto.log
../../guestbin/wait-for.sh --match 'imported CRL.*CN=north.testing.libreswan.org' -- cat /tmp/pluto.log
../../guestbin/wait-for.sh --match 'imported CRL.*CN=road.testing.libreswan.org' -- cat /tmp/pluto.log
../../guestbin/wait-for.sh --match 'imported CRL.*CN=east.testing.libreswan.org' -- cat /tmp/pluto.log
../../guestbin/wait-for.sh --match 'imported CRL.*CN=Libreswan test CA for mainca' -- cat /tmp/pluto.log
# check the queue is drained
ipsec auto --listcrls
