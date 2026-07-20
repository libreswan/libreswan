# stop the CREATE_CHILD_SA making it out
ipsec whack --impair block_outbound:yes

ipsec up --async west-cuckoo # sanitize-retransmits
/testing/guestbin/wait-for-pluto.sh '"west-cuckoo" #3: sent CREATE_CHILD_SA request'
