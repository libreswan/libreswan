# NOTE: this is shared by a number of tests
: check out the myid that I concluded with
ipsec auto --status | grep '%myid ='
: ==== cut ====
cat /tmp/pluto.log
ipsec look
ipsec auto --status
: ==== tuc ====
: ==== end ====
