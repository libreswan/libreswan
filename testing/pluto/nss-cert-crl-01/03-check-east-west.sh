ipsec crlutil -L | grep mainca
ipsec auto --listall | grep -A10 "List of CRLs" | grep -E 'Issuer|Entry|Serial'
: ==== cut ====
ipsec auto --status
: ==== tuc ====
