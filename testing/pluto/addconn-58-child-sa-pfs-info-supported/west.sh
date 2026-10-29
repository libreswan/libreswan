/testing/guestbin/swan-prep --nokeys
ipsec addconn --config west.conf --configsetup=child-sa-pfs-info-supported
ipsec addconn --config child-sa-pfs-info-supported-yes.conf --configsetup=child-sa-pfs-info-supported
ipsec addconn --config child-sa-pfs-info-supported-no.conf --configsetup=child-sa-pfs-info-supported
