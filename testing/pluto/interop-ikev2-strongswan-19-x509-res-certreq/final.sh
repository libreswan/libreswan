if [ -f /var/run/pluto/pluto.pid ]; then ../../guestbin/ipsec-kernel-state.sh\n../../guestbin/ipsec-kernel-policy.sh ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then strongswan status && grep "invalid X509 hash length" /tmp/charon.log ; fi
