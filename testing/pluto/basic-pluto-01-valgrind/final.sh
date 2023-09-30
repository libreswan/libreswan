../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
# ==== cut ====
ipsec auto --status
# ==== tuc ====
ipsec whack --shutdown
