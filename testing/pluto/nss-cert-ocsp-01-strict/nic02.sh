journalctl --no-pager -b -xn -u ocspd.service | egrep "status|request" | sed "s/^.*: //"
: ==== end ====
