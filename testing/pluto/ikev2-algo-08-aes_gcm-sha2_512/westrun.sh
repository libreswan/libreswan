ipsec auto --up westnet-eastnet-ipv4-psk-ikev2-gcm-c
MIN_IKEV2_NONCE_SHA2_512="32"
emit_nonce=$(sed -n -e 's/.* emitting \([0-9]*\) raw bytes of IKEv2 nonce .*$/\1/p' /tmp/pluto.log)
recv_nonce=$(expr $(grep -A 3 'parse IKEv2 Nonce Payload:' /tmp/pluto.log | sed -n -e 's/^.*length: \([^ ]\+\) .*$/\1/p') - 4)
echo "emitted nonce length (${emit_nonce}) should be >= minimum accepted nonce length for SHA2_512 (${MIN_IKEV2_NONCE_SHA2_512})"
test ${emit_nonce} -ge ${MIN_IKEV2_NONCE_SHA2_512} || echo failed
echo "received nonce length (${recv_nonce}) should be >= minimum accepted nonce length for SHA2_512 (${MIN_IKEV2_NONCE_SHA2_512})"
test ${recv_nonce} -ge ${MIN_IKEV2_NONCE_SHA2_512} || echo failed
echo done
