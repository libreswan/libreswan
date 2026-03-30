# east 01-init-east.sh

east# ../../guestbin/swan-prep

# west 02-init-netbsdwest.sh

west# ../../guestbin/prep.sh

# east 03-start-east.sh

east# ipsec start
east# ../../guestbin/wait-until-pluto-started
east# ipsec add interop

# west 04-start-netbsdwest.sh

west# ipsec start
west# ../../guestbin/wait-until-pluto-started
west# ipsec add interop

# west 05-initiate-netbsdwest.sh

west# ipsec up interop
west# ipsec _kernel state
west# ipsec _kernel policy

# west 07-ping-netbsdwest.sh

west# ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254

# east 08-traffic-east.sh

east# ipsec trafficstatus

# west 09-traffic-netbsdwest.sh

west# ipsec trafficstatus

