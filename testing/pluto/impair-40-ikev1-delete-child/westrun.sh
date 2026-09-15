ipsec up west-east # sanitize-retransmits
# send to delete child SAs
ipsec whack --impair v1_isakmp_delete_payload:duplicate
ipsec whack --impair v1_ipsec_delete_payload:duplicate
ipsec delete west-east # sanitize-retransmits
