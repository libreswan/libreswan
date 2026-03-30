# east 01-init-netbsdeast.sh

east# ../../guestbin/prep.sh

# west 02-init-freebsdwest.sh

west# ../../guestbin/prep.sh

# east 03-start-netbsdeast.sh

east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec add interop

# west 04-start-freebsdwest.sh

west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec add interop

# west 05-initiate-freebsdwest.sh

west# ipsec up interop
west# ipsec _kernel state
west# ipsec _kernel policy

# west 07-ping-freebsdwest.sh

west# ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

# east 08-traffic-netbsdeast.sh

east# ipsec trafficstatus

# west 09-traffic-freebsdwest.sh

west# ipsec trafficstatus

