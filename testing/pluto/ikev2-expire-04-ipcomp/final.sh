ipsec _kernel state
ipsec _kernel policy
# should match only on west, exactly twice
grep "initiating rekey to replace Child SA" OUTPUT/$(hostname).pluto.log
# should be absent
grep "initiating Child SA using IKE SA" OUTPUT/$(hostname).pluto.log || echo "success"
# should hit twice on west only
grep "received .* EXPIRE " OUTPUT/$(hostname).pluto.log | sed 's/for SPI 0x.*$/for SPI .../'
