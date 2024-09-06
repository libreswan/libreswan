ipsec whack --impair v1_emit_quick_id:0
ipsec up west
ipsec whack --impair v1_emit_quick_id:1
ipsec up west
ipsec whack --impair v1_emit_quick_id:3
ipsec up west

echo done
