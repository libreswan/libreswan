/testing/guestbin/swan-prep
ipsec addconn --config 2.32-1.conf --configsetup | grep nhelpers
ipsec addconn --config 2.32.conf --configsetup | grep nhelpers
ipsec addconn --config 2.32+1.conf --configsetup | grep nhelpers
