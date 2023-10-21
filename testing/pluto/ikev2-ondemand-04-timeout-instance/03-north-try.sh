# check policy installed
../../guestbin/ipsec-kernel-policy.sh

# initiate a connection
../../guestbin/ping-once.sh --forget -I 192.0.3.254 192.0.2.254
../../guestbin/wait-for.sh --match '^".*#1: sent IKE_SA_INIT request' -- cat /tmp/pluto.log
../../guestbin/ipsec-kernel-policy.sh

# wait for it to fail
../../guestbin/wait-for.sh --match ' second timeout exceeded after ' -- cat /tmp/pluto.log
../../guestbin/ipsec-kernel-policy.sh

# let larval state expire
../../guestbin/wait-for.sh --no-match 'spi 0x00000000' -- ../../guestbin/ipsec-kernel-state.sh
