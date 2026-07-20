# stop the CREATE_CHILD_SA making it out
ipsec whack --impair block_outbound:yes

ipsec up --async west-cuckoo
/testing/guestbin/wait-for-pluto.sh --match '"west-cuckoo" #3: sent Quick Mode request'
