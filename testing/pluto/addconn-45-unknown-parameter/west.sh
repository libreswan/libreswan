/testing/guestbin/swan-prep

# expect this to fail
ipsec start

# and why; --output==format
journalctl --output cat -xeu ipsec.service | grep FATAL

# and addconn
ipsec addconn --checkconfig --config /etc/ipsec.conf
