ipsec auto --up westnet-eastnet-ipv4-psk-ikev2-gcm-c
MIN_IKEV2_NONCE_SHA2_512="32"
emit_nonce="$(grep 'IKEv2 nonce into IKEv2 Nonce Payload' /tmp/pluto.log | grep 'emitting' | sed 's/^.*emitting \([^ ]\+\) raw .*$/\1/' | head -n 1)"
recv_nonce="$(expr $(grep -A 3 '***parse IKEv2 Nonce Payload:' /tmp/pluto.log | grep 'length:' | sed 's/^.*length: \([^ ]\+\) .*$/\1/' | head -n 1) - 4)"
echo "emited nonce length (${emit_nonce}) should be >= minimum accepted nonce length for SHA2_512 (${MIN_IKEV2_NONCE_SHA2_512})"
test ${emit_nonce} -ge ${MIN_IKEV2_NONCE_SHA2_512} || echo failed
echo "received nonce length (${recv_nonce}) should be >= minimum accepted nonce length for SHA2_512 (${MIN_IKEV2_NONCE_SHA2_512})"
test ${recv_nonce} -ge ${MIN_IKEV2_NONCE_SHA2_512} || echo failed
echo done
