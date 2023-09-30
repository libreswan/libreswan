grep -e 'parse IKEv2 Certificate' -e 'emit IKEv2 Certificate' -e 'ikev2 cert encoding' /tmp/pluto.log
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
