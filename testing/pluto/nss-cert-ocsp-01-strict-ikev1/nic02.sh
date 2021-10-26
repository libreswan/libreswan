journalctl --no-pager -b -xn -u ocspd.service | grep -E "status|request" | sed "s/^.*: //"
: ==== end ====
