# Proper test connection, should work
ipsec whack --impair none
ipsec whack --impair suppress-retransmits
../../guestbin/libreswan-up-down.sh westnet-eastnet --alive -I 192.0.1.254 192.0.2.254

# Quick:
ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair suppress-retransmits
ipsec whack --impair v1-hash-exchange:quick
# HASH payload omitted - should fail
ipsec whack --impair v1-hash-payload:omit
../../guestbin/libreswan-up-down.sh westnet-eastnet --down -I 192.0.1.254 192.0.2.254
# HASH payload empty - should fail
ipsec whack --impair v1-hash-payload:empty
../../guestbin/libreswan-up-down.sh westnet-eastnet --down -I 192.0.1.254 192.0.2.254
# HASH payload badly calculated - should fail
ipsec whack --impair v1-hash-payload:0
../../guestbin/libreswan-up-down.sh westnet-eastnet --down -I 192.0.1.254 192.0.2.254
echo done

# Delete
ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair suppress-retransmits
ipsec whack --impair v1-hash-exchange:delete
# HASH payload omitted - delete should fail
ipsec whack --impair v1-hash-payload:omit
../../guestbin/libreswan-up-down.sh westnet-eastnet --alive -I 192.0.1.254 192.0.2.254
# HASH payload empty - delete should fail
ipsec whack --impair v1-hash-payload:empty
../../guestbin/libreswan-up-down.sh westnet-eastnet --alive -I 192.0.1.254 192.0.2.254
# HASH payload badly calculated - delete should fail
ipsec whack --impair v1-hash-payload:0
../../guestbin/libreswan-up-down.sh westnet-eastnet --alive -I 192.0.1.254 192.0.2.254
echo done

# XAUTH:
ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair suppress-retransmits
ipsec whack --impair v1-hash-exchange:xauth
# HASH payload omitted - XAUTH should fail
ipsec whack --impair v1-hash-payload:omit
../../guestbin/libreswan-up-down.sh westnet-eastnet --alive -I 192.0.1.254 192.0.2.254
# HASH payload empty - XAUTH should fail
ipsec whack --impair v1-hash-payload:empty
../../guestbin/libreswan-up-down.sh westnet-eastnet --alive -I 192.0.1.254 192.0.2.254
# HASH payload badly calculated - XAUTH should fail
ipsec whack --impair v1-hash-payload:0
../../guestbin/libreswan-up-down.sh westnet-eastnet --alive -I 192.0.1.254 192.0.2.254
echo done

# INFO
ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair suppress-retransmits
ipsec whack --impair v1-hash-exchange:notification
# HASH payload omitted - INFO should fail
ipsec whack --impair v1-hash-payload:omit
../../guestbin/libreswan-up-down.sh westnet-eastnet --alive -I 192.0.1.254 192.0.2.254
# HASH payload empty - INFO should fail
ipsec whack --impair v1-hash-payload:empty
../../guestbin/libreswan-up-down.sh westnet-eastnet --alive -I 192.0.1.254 192.0.2.254
# HASH payload badly calculated - INFO should fail
ipsec whack --impair v1-hash-payload:0
../../guestbin/libreswan-up-down.sh westnet-eastnet --alive -I 192.0.1.254 192.0.2.254

echo done
