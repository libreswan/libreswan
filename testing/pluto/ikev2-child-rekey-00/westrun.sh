ipsec up rekey  # sanitize-retransmits
ipsec up rekey1 # sanitize-retransmits
ipsec up rekey2 # sanitize-retransmits

# Do an IKE rekey by specifying the IKE SA's connection
ipsec whack --rekey-ike --name rekey  # sanitize-retransmits

# Do an IKE rekey but specify the connection of one of the Child SA
# cukoos.  Is the error what we really want?  Or would we want it to
# find the shared IKE SA?
ipsec whack --rekey-ike --name rekey2 # sanitize-retransmits

# Rekey should not trigger IKE_SA_INIT exchanges but CREATE_CHILD_SA
# exchanges
ipsec whack --rekey-child --name rekey1 # sanitize-retransmits
ipsec whack --rekey-child --name rekey  # sanitize-retransmits
ipsec whack --rekey-child --name rekey2 # sanitize-retransmits

echo done
