../../guestbin/prep.sh

ipsec initnss

# Test 1: --config then --logfile (command line overrides config)
ipsec pluto --config /etc/ipsec.conf --logfile /tmp/test.log
../../guestbin/wait-until-pluto-started
ipsec whack --status | grep logfile=
ipsec whack --shutdown
test -s /tmp/test.log && echo "logfile /tmp/test.log has content"

# Test 2: --logfile then --config (config overrides command line)
ipsec pluto --logfile /tmp/test2.log --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec whack --status | grep logfile=
ipsec whack --shutdown

# Test 3: --config then --logfile '' (empty string, falls back to syslog)
ipsec pluto --config /etc/ipsec.conf --logfile ''
../../guestbin/wait-until-pluto-started
ipsec whack --status | grep logfile=
ipsec whack --shutdown

# Test 4: --stderrlog with --selftest
ipsec pluto --stderrlog --selftest --config /etc/ipsec.conf > /tmp/stderr.log 2>&1
test -s /tmp/stderr.log && echo "stderr output captured"

# Test 5: --stderrlog + --logfile with --selftest (stderrlog takes precedence)
rm -f /tmp/ignored.log
ipsec pluto --stderrlog --logfile /tmp/ignored.log --selftest --config /etc/ipsec.conf > /tmp/stderr5.log 2>&1
test -s /tmp/stderr5.log && echo "stderr output captured"
test -s /tmp/ignored.log && echo "ignored.log has content" || echo "ignored.log is empty or missing"

# Test 6: --logfile '' then --config (config overrides empty, restores file logging)
ipsec pluto --logfile '' --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec whack --status | grep logfile=
ipsec whack --shutdown
test -s /tmp/pluto.log && echo "logfile /tmp/pluto.log has content"

# Test 7: --config then --stderrlog with --selftest (config first, stderrlog after)
ipsec pluto --config /etc/ipsec.conf --stderrlog --selftest > /tmp/stderr7.log 2>&1
test -s /tmp/stderr7.log && echo "stderr output captured"

# Test 8: --config then --logfile then --stderrlog with --selftest (no warning, stderr wins)
rm -f /tmp/ignored8.log
ipsec pluto --config /etc/ipsec.conf --logfile /tmp/ignored8.log --stderrlog --selftest > /tmp/stderr8.log 2>&1
test -s /tmp/stderr8.log && echo "stderr output captured"
test -s /tmp/ignored8.log && echo "ignored8.log has content" || echo "ignored8.log is empty or missing"
