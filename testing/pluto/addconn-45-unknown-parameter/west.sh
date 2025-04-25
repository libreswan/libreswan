/testing/guestbin/swan-prep --nokeys

# broken invocation

# fail as nothing to do
ipsec addconn --config /dne.conf
# fail as file not found
ipsec addconn --config /dne.conf connection
# fail as nothing to do
ipsec addconn --debug
# fail as nothing to do, --debug= ignored
ipsec addconn --debug=asdfasdf
# fail as nothing to do, --config not eaten
ipsec addconn --debug --config /dne.conf

# broken config setup

# will fail
ipsec pluto --config bad-config-setup-key.conf
# should fail but doesn't, hence shutdown
ipsec pluto --config bad-config-setup-value.conf
ipsec whack --shutdown
cp /tmp/pluto.log OUTPUT/bad-config-setup-value.log

# broken conn section; should be grumpy but ignored

ipsec pluto --config bad-conn-key.conf
ipsec whack --shutdown
cp /tmp/pluto.log OUTPUT/bad-conn-key.log

ipsec pluto --config bad-conn-value.conf
ipsec whack --shutdown
cp /tmp/pluto.log OUTPUT/bad-conn-value.log

# now try to add the corresponding conn

ipsec start
# and why; --output==format
journalctl --output cat -xeu ipsec.service | grep -e FATAL -e warning

ipsec addconn --config bad-conn-key.conf    bad-conn-key
ipsec addconn --config bad-conn-value.conf  bad-conn-value
