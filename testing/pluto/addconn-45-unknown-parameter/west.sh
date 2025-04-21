/testing/guestbin/swan-prep

# expect both to fail?
ipsec pluto --config bad-setup-key.conf
ipsec pluto --config bad-setup-value.conf

# expect this to work; but to be grumpy
ipsec pluto --config /etc/ipsec.conf
ipsec start
# and why; --output==format
journalctl --output cat -xeu ipsec.service | grep -e FATAL -e warning

# and addconn
ipsec addconn --checkconfig --config /etc/ipsec.conf
ipsec addconn --config bad-conn-key.conf    bad-conn-key
ipsec addconn --config bad-conn-value.conf  bad-conn-value
