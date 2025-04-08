/testing/guestbin/swan-prep --nokeys

cp policy /etc/ipsec.d/policies/road

# need to use pluto
ipsec pluto --config /etc/ipsec.conf --expire-shunt-interval 5s --leak-detective
../../guestbin/wait-until-pluto-started

# Load and dump an ipsec.conf connection.  The whack command should
# define something identical, it doesn't:
#
#   - whack, because of %opportunisticgroup sets +rKOD aka remote DNS
#     key on-demand
#
#   - addconn adds CERT_ALWAYSSEND; whack defaults to CERT_SENDIFASKED

ipsec add road
ipsec connectionstatus road

echo "initdone"
