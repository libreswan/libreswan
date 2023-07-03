ipsec auto --up west-east
# send to delete child SAs
ipsec whack --impair v1_isakmp_delete_payload:duplicate
ipsec whack --impair v1_ipsec_delete_payload:duplicate
ipsec auto --delete west-east
