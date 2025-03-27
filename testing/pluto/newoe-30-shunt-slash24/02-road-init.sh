/testing/guestbin/swan-prep --nokeys

# ensure for tests acquires expire before our failureshunt=2m
echo 30 > /proc/sys/net/core/xfrm_acq_expires
ip -s xfrm monitor > /tmp/xfrm-monitor.out & sleep 1

cp policy /etc/ipsec.d/policies/road

ipsec start
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
