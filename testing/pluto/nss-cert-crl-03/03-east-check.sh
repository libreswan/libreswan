# Check that mainca is present
ipsec crlutil -L | grep mainca

# DANGER: race.
#
# Wait for the CRL fetch helper to be triggered and fetch the CRLs.
# The first fetch, which happens happens after 5s, may or may-not be
# too quick for the exchange.
../../guestbin/wait-for-pluto.sh 'imported CRL'
# check the queue is drained
ipsec auto --listcrls
