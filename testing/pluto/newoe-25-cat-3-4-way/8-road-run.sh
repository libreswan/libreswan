# trigger OE to east, west,and north
# east is NATed. should have address from the addresspool
../../guestbin/fping-short.sh --lossy 15 192.1.2.23
# west and north are not NATed
../../guestbin/fping-short.sh --lossy 15 192.1.2.45
../../guestbin/fping-short.sh --lossy 15 192.1.3.33
echo run done
