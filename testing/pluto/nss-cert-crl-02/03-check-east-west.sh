crlutil -L -d sql:/etc/ipsec.d | grep mainca
ipsec auto --listall | grep -A10 "List of CRLs" | egrep 'Issuer|Entry|Serial'
: ==== cut ====
ipsec auto --status
: ==== tuc ====
