# Confirm expired IPsec SA will not trigger a liveness probe
grep "liveness: .* was replaced by "  /tmp/pluto.log
